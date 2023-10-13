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
	InstanceID          string
	IsLeader            bool
	IngressInterface    NetworkInterface
	ManagementInterface NetworkInterface
	VIPAddress          string
	Peers               []string
	PeerInterfaces      []NetworkInterface
	PeerInstances       []types.Instance
}

type NetworkInterface struct {
	DeviceName     string
	PrimaryAddress string
	ENIID          string
	Description    string
	SubnetID       string
	SubnetCIDR     net.IPNet
}

func (n NetworkInterface) String() string {
	return fmt.Sprintf("deviceName=%s addr=%s eniid=%s desc=%s subnet=%s", n.DeviceName, n.PrimaryAddress, n.ENIID, n.Description, n.SubnetID)
}

const (
	AWSTagNameASG           = "aws:autoscaling:groupName"
	AWSTagNameNeuwerkLeader = "neuwerk:leader"
	AWSTagNameNeuwerkVIP    = "neuwerk:vip"

	ManagementDeviceDescription = "management"
	IngressDeviceDescription    = "ingress"
)

var logger = log.DefaultLogger

// The AWS integration makes assumptions about how neuwerk is deployed:
// 1. Neuwerk is deployed as an ASG
// 2. One instance is selected as leader
// 3. each instance has two ENIs with a pre-defined description for its own purpose: ingress or management
//
// The integration mechanism will do the following:
// 1. discover peers by listing instances from the sam ASG
// 2. discover if this instance is a leader
// 3. disable the src/dst check on the ingress interfaces
//
// Note: please refer to tf/ directory to see how it is supposed to be set up.
func Apply(ctx context.Context, ctrlConfig *controller.ControllerConfig) error {
	discovery, err := Discover(ctx)
	if err != nil {
		return fmt.Errorf("unable to discover peers: %w", err)
	}
	logger.Info("discovered peers", "peers", discovery.Peers)
	err = disableSrcDstCheck(ctx, discovery.IngressInterface.ENIID)
	if err != nil {
		return fmt.Errorf("unable to disable src/dst check: %w", err)
	}
	err = disableSrcDstCheck(ctx, discovery.ManagementInterface.ENIID)
	if err != nil {
		return fmt.Errorf("unable to disable src/dst check: %w", err)
	}

	lnk, err := netlink.LinkByName(discovery.IngressInterface.DeviceName)
	if err != nil {
		return err
	}
	logger.Info("assigning vip", "vip", discovery.VIPAddress)
	err = netlink.AddrReplace(lnk, &netlink.Addr{
		LinkIndex: lnk.Attrs().Index,
		IPNet: &net.IPNet{
			IP:   net.ParseIP(discovery.VIPAddress),
			Mask: discovery.IngressInterface.SubnetCIDR.Mask,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to assign vip: %w", err)
	}

	if discovery.IsLeader {
		// check availability of peers
		// if they're available: join them
		// if not: bootstrap new cluster
		var peerAvailable bool
		for _, addr := range discovery.Peers {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3322", addr), time.Millisecond*1500)
			if err != nil {
				logger.Info("peer is not available", "addr", addr)
				continue
			}
			conn.Close()
			peerAvailable = true
			break
		}

		if peerAvailable {
			ctrlConfig.Peers = append(ctrlConfig.Peers, discovery.Peers...)
		} else {
			ctrlConfig.Peers = []string{}
		}
	} else {
		// not leader: try to connect with peers
		ctrlConfig.Peers = append(ctrlConfig.Peers, discovery.Peers...)
	}
	if discovery.IngressInterface.DeviceName != "" {
		ctrlConfig.DeviceName = discovery.IngressInterface.DeviceName
	}

	ctrlConfig.CoordinatorReconcilerFunc = ReconcileCoordinator
	ctrlConfig.MgmtAddr = discovery.ManagementInterface.PrimaryAddress
	ctrlConfig.IngressAddr = discovery.IngressInterface.PrimaryAddress
	ctrlConfig.DNSListenHostPort = discovery.VIPAddress + ":53"
	ctrlConfig.VIPAddr = discovery.VIPAddress

	return nil
}

func disableSrcDstCheck(ctx context.Context, eniID string) error {
	// disable src/dst check on the ingress interface.
	// we can not do this via launch template, have to do this from the box itself
	logger.Info("disabling src/dest check", "iface", eniID)
	cfg, err := GetConfig(ctx)
	if err != nil {
		return err
	}
	var falseVal bool
	ec2c := ec2.NewFromConfig(*cfg)
	_, err = ec2c.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: &eniID,
		SourceDestCheck: &types.AttributeBooleanValue{
			Value: &falseVal,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to disable src/dst check: %w", err)
	}
	return nil
}

func ReassignVIP(ctx context.Context, discovery *DiscoveryOutput) error {
	cfg, err := GetConfig(ctx)
	if err != nil {
		return err
	}
	ec2c := ec2.NewFromConfig(*cfg)

	_, err = ec2c.AssignPrivateIpAddresses(ctx, &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: &discovery.IngressInterface.ENIID,
		AllowReassignment:  aws.Bool(true),
		PrivateIpAddresses: []string{discovery.VIPAddress},
	})
	if err != nil {
		return fmt.Errorf("unable to assign private ip: %w", err)
	}

	return nil
}

var ErrNoPriorityAssigned = errors.New("no priority set")

func Discover(ctx context.Context) (*DiscoveryOutput, error) {
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
		out.PeerInstances = append(out.PeerInstances, res.Instances...)
		for _, ins := range res.Instances {
			if ins.State.Name != types.InstanceStateNameRunning {
				continue
			}
			for _, tag := range ins.Tags {
				if *tag.Key == AWSTagNameNeuwerkVIP {
					addr, _, err := net.ParseCIDR(*tag.Value)
					if err != nil {
						return nil, fmt.Errorf("unabke to parse vip %q: %w", *tag.Value, err)
					}
					out.VIPAddress = addr.String()
				}
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
							Description:    *iface.Description,
							SubnetID:       *iface.SubnetId,
						}
					}

					if *iface.Description == ManagementDeviceDescription {
						out.ManagementInterface = NetworkInterface{
							DeviceName:     lnk.Attrs().Name,
							PrimaryAddress: *iface.PrivateIpAddress,
							ENIID:          *iface.NetworkInterfaceId,
							Description:    *iface.Description,
							SubnetID:       *iface.SubnetId,
						}
					}

					// no need to continue further
					continue
				}

				out.PeerInterfaces = append(out.PeerInterfaces, NetworkInterface{
					DeviceName:     "", // not known
					PrimaryAddress: *iface.PrivateIpAddress,
					ENIID:          *iface.NetworkInterfaceId,
					Description:    *iface.Description,
					SubnetID:       *iface.SubnetId,
				})

				// skip ingress device, peers are connecting to the management interface
				if *iface.Description == IngressDeviceDescription {
					logger.V(2).Info("skipping ingress device", "instance", *ins.InstanceId, "iface", *iface.Description, "addr", *iface.PrivateIpAddress)
					continue
				}

				logger.V(2).Info("adding peer", "instance", *ins.InstanceId, "iface", *iface.Description, "addr", *iface.PrivateIpAddress)
				out.Peers = append(out.Peers, *iface.PrivateIpAddress)
			}
		}
	}

	// when used from e2e tests, we do not have an ingress interface,
	// hence we need to return early
	if out.IngressInterface.SubnetID == "" {
		return out, nil
	}

	subnetOut, err := ec2c.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []string{out.IngressInterface.SubnetID},
	})
	if err != nil {
		return nil, err
	}
	for _, subnet := range subnetOut.Subnets {
		_, ipNet, err := net.ParseCIDR(*subnet.CidrBlock)
		if err != nil {
			return nil, err
		}
		out.IngressInterface.SubnetCIDR = *ipNet
	}

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
