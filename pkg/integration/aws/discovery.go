package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/moolen/neuwerk/pkg/controller"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/vishvananda/netlink"
)

type DiscoveryOutput struct {
	ClusterName         string
	InstanceID          string
	IsLeader            bool
	IngressInterface    NetworkInterface
	ManagementInterface NetworkInterface
	EgressInterface     NetworkInterface

	Peers []string
}

type NetworkInterface struct {
	DeviceName     string
	ENIID          string
	PrimaryAddress string
}

func (n NetworkInterface) String() string {
	return fmt.Sprintf("deviceName=%s addr=%s eniid=%s", n.DeviceName, n.PrimaryAddress, n.ENIID)
}

const (
	AWSTagNameASG            = "aws:autoscaling:groupName"
	AWSTagNameNeuwerkLeader  = "neuwerk:leader"
	AWSTagNameNeuwerkVIP     = "neuwerk:vip"
	AWSTagNameNeuwerkCluster = "neuwerk:cluster"
	AWSTagEgress             = "neuwerk:egress"

	ManagementDeviceDescription = "management"
	IngressDeviceDescription    = "ingress"
	EgressDeviceDescription     = "egress"
)

var logger = log.DefaultLogger

// The integration mechanism will do the following:
// 1. discover peers by listing EC2 instances matching well known tags
// 2. if this is a leader: modify the ingress subnet route table and point the default route
//
// Note: please refer to tf/ directory to see how it is supposed to be set up.
func Apply(ctx context.Context, ctrlConfig *controller.ControllerConfig) error {
	discovery, err := Discover(ctx)
	if err != nil {
		return fmt.Errorf("unable to discover peers: %w", err)
	}

	logger.Info("discovered peers", "peers", discovery.Peers)

	ctrlConfig.Peers = append(ctrlConfig.Peers, discovery.Peers...)

	ctrlConfig.IngressDeviceName = discovery.IngressInterface.DeviceName
	ctrlConfig.EgressDeviceName = discovery.EgressInterface.DeviceName

	ctrlConfig.CoordinatorReconcilerFunc = ReconcileCoordinator
	ctrlConfig.ManagementAddress = discovery.ManagementInterface.PrimaryAddress
	ctrlConfig.IngressAddress = discovery.IngressInterface.PrimaryAddress
	ctrlConfig.DNSListenHostPort = discovery.IngressInterface.PrimaryAddress + ":53"

	return nil
}

func updateRouteTable(ctx context.Context, discovery *DiscoveryOutput) error {
	logger.Info("updating route table")
	cfg, err := GetConfig(ctx)
	if err != nil {
		return err
	}
	svc := ec2.NewFromConfig(*cfg)
	rts, err := svc.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:" + AWSTagNameNeuwerkCluster),
				Values: []string{discovery.ClusterName},
			},
		},
	})
	if err != nil {
		return err
	}
	if len(rts.RouteTables) == 0 {
		return fmt.Errorf("could not find neuwerk route tables")
	}

tableLoop:
	for _, rt := range rts.RouteTables {
		logger.Info("route table", "route table", rt.RouteTableId)

		// find `ingress` route table with ingress address
		var matchedCIDR bool
		for _, assoc := range rt.Associations {
			if assoc.SubnetId == nil {
				continue
			}
			sn, err := svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
				SubnetIds: []string{*assoc.SubnetId},
			})
			if err != nil {
				return fmt.Errorf("unable to describe subnet: %w", err)
			}
			for _, sn := range sn.Subnets {
				_, ipnet, err := net.ParseCIDR(*sn.CidrBlock)
				if err != nil {
					return err
				}
				if ipnet.Contains(net.ParseIP(discovery.IngressInterface.PrimaryAddress)) {
					matchedCIDR = true
				}
			}
		}

		if !matchedCIDR {
			continue tableLoop
		}

		// catch all route must point to this ingress ENI
		destinationCIDR := aws.String("0.0.0.0/0")
		for _, r := range rt.Routes {
			logger.Info("route", "route", r)
			if *r.DestinationCidrBlock == *destinationCIDR {
				logger.Info("reconciling route", "route", r, "dst-cidr", *destinationCIDR, "target-eni", discovery.IngressInterface.ENIID)
				_, err := svc.ReplaceRoute(ctx, &ec2.ReplaceRouteInput{
					RouteTableId:         rt.RouteTableId,
					DestinationCidrBlock: destinationCIDR,
					NetworkInterfaceId:   &discovery.IngressInterface.ENIID,
				})
				if err != nil {
					return err
				}
				continue tableLoop
			}
		}
		logger.Info("creating route", "table", rt.RouteTableId, "dst-cidr", *destinationCIDR, "target-eni", discovery.IngressInterface.ENIID)
		_, err = svc.CreateRoute(ctx, &ec2.CreateRouteInput{
			RouteTableId:         rt.RouteTableId,
			DestinationCidrBlock: destinationCIDR,
			NetworkInterfaceId:   &discovery.IngressInterface.ENIID,
		})
		if err != nil {
			return fmt.Errorf("unable to create route: %w", err)
		}
	}
	return nil
}

var ErrNoPriorityAssigned = errors.New("no priority set")

func Discover(parentCtx context.Context) (*DiscoveryOutput, error) {
	ctx, cancel := context.WithTimeout(parentCtx, time.Second*5)
	defer cancel()
	out := &DiscoveryOutput{}
	cfg, err := GetConfig(ctx)
	if err != nil {
		return nil, err
	}

	ec2c := ec2.NewFromConfig(*cfg)
	instanceOut, err := ec2c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []string{"neuwerk"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to describe instances: %w", err)
	}

	_, err = GetMetadata(ctx, *cfg, "tags/instance/"+AWSTagNameNeuwerkLeader)
	if err != nil {
		logger.Info("instance is not leader")
	} else {
		logger.Info("instance is leader")
		out.IsLeader = true
	}

	out.ClusterName, err = GetMetadata(ctx, *cfg, "tags/instance/"+AWSTagNameNeuwerkCluster)
	if err != nil {
		return nil, fmt.Errorf("unable to get cluster name: %w", err)
	}

	out.InstanceID, err = GetMetadata(ctx, *cfg, "instance-id")
	if err != nil {
		return nil, err
	}
	logger.V(2).Info("found instance id", "id", out.InstanceID)

	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	// map ip addr to link
	addrToLink := map[string]netlink.Link{}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			addrToLink[addr.IP.String()] = link
		}
	}

	for _, res := range instanceOut.Reservations {
		for _, ins := range res.Instances {
			if ins.State.Name != types.InstanceStateNameRunning {
				continue
			}
			for _, iface := range ins.NetworkInterfaces {
				if iface.PrivateIpAddress == nil {
					continue
				}

				// this is us, not a peer
				if *ins.InstanceId == out.InstanceID {
					lnk, ok := addrToLink[*iface.PrivateIpAddress]
					if !ok {
						// no matching device exists. wut.
						continue
					}
					// find ingress interface device name, e.g. eth0, ens5 etc.
					// we'll apply the eBPF filters to only this device
					if *iface.Description == IngressDeviceDescription {
						out.IngressInterface = NetworkInterface{
							DeviceName:     lnk.Attrs().Name,
							PrimaryAddress: *iface.PrivateIpAddress,
							ENIID:          *iface.NetworkInterfaceId,
						}
					}

					if *iface.Description == ManagementDeviceDescription {
						out.ManagementInterface = NetworkInterface{
							DeviceName:     lnk.Attrs().Name,
							PrimaryAddress: *iface.PrivateIpAddress,
							ENIID:          *iface.NetworkInterfaceId,
						}
					}

					if *iface.Description == EgressDeviceDescription {
						out.EgressInterface = NetworkInterface{
							DeviceName:     lnk.Attrs().Name,
							PrimaryAddress: *iface.PrivateIpAddress,
							ENIID:          *iface.NetworkInterfaceId,
						}
					}

					// no need to continue further
					continue
				}

				// skip ingress device, peers are connecting to the management interface
				if *iface.Description == IngressDeviceDescription {
					logger.V(2).Info("skipping ingress device", "instance", *ins.InstanceId, "iface", *iface.Description, "addr", *iface.PrivateIpAddress)
					continue
				}

				if *iface.Description == EgressDeviceDescription {
					logger.V(2).Info("skipping egress device", "instance", *ins.InstanceId, "iface", *iface.Description, "addr", *iface.PrivateIpAddress)
					continue
				}

				logger.V(2).Info("adding peer", "instance", *ins.InstanceId, "iface", *iface.Description, "addr", *iface.PrivateIpAddress)
				out.Peers = append(out.Peers, *iface.PrivateIpAddress)
			}
		}
	}

	logger.Info("discovery interface info", "ingress", out.IngressInterface, "egress", out.EgressInterface, "mgmt", out.ManagementInterface)
	return out, nil
}

func GetConfig(ctx context.Context) (*aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	// discover region we're running in (needed for subsequent calls to asg/ec2 APIs)
	imdsClient := imds.NewFromConfig(cfg)
	regOut, err := imdsClient.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return nil, fmt.Errorf("unable to get region: %w", err)
	}
	cfg.Region = regOut.Region
	return &cfg, nil
}

func GetMetadata(ctx context.Context, cfg aws.Config, path string) (string, error) {
	metac := imds.NewFromConfig(cfg)
	out, err := metac.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve metadata %s: %w", path, err)
	}
	defer out.Content.Close()
	val, err := io.ReadAll(out.Content)
	if err != nil {
		return "", fmt.Errorf("unable to read metadata %s: %w", path, err)
	}

	return string(val), nil
}
