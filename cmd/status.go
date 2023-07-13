package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/buraksezer/olric"
	"github.com/cilium/ebpf"
	"github.com/moolen/neuwerk/pkg/bpf"
	"github.com/moolen/neuwerk/pkg/controller"
	"github.com/moolen/neuwerk/pkg/integration/aws"
	"github.com/moolen/neuwerk/pkg/util"
	"github.com/spf13/cobra"
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := dumpAWS()
		if err != nil {
			logger.Error(err, "unable to dump aws stuff")
		}

		err = dumpConfig(bpffs)
		if err != nil {
			logger.Error(err, "unable to dump config")
		}
	},
}

func dumpAWS() error {
	return nil
}

func dumpConfig(bpffs string) error {
	discovery, err := aws.Discover(context.Background())
	if err != nil {
		return fmt.Errorf("unable to discover peers: %w", err)
	}

	fmt.Println("\n==============")
	fmt.Println("aws:discovery")
	fmt.Println("--------------")
	fmt.Printf("leader: %t\n", discovery.IsLeader)
	fmt.Printf("ingress interface: %s\n", discovery.IngressInterface.String())
	fmt.Printf("mgmt interface: %s\n", discovery.ManagementInterface.String())
	fmt.Printf("vip: %s\n", discovery.VIPAddress)
	fmt.Printf("peers: %v\n", discovery.Peers)
	for i, iface := range discovery.PeerInterfaces {
		fmt.Printf("peer interface[%d]: %s\n", i, iface.String())
	}

	coll, err := bpf.Load(bpffs, discovery.IngressInterface.DeviceName, discovery.IngressInterface.PrimaryAddress, dnsListenHostPort)
	if err != nil {
		return err
	}

	fmt.Println("\n==============")
	fmt.Println("bpf:NetworkPolicy")
	fmt.Println("--------------")
	it := coll.NetworkPolicies.Iterate()
	var key uint32
	var mapId uint32
	for it.Next(&key, &mapId) {
		m, err := ebpf.NewMapFromID(ebpf.MapID(mapId))
		if err != nil {
			return err
		}
		polIt := m.Iterate()

		var polKey bpf.PolicyKey
		var polVal uint32
		for polIt.Next(&polKey, &polVal) {
			fmt.Printf("netpol=%d addr=%s port=%d\n", key, util.ToIP(polKey.UpstreamAddr), util.ToHost16(polKey.UpstreamPort))
		}
	}

	fmt.Println("\n==============")
	fmt.Println("bpf:PktTrack")
	fmt.Println("--------------")
	it = coll.PktTrack.Iterate()
	var timestamp uint64
	for it.Next(&key, &timestamp) {
		unixtime := time.Unix(0, int64(timestamp))
		fmt.Printf("key=%d addr=%s timestamp=%d unixtime=%s\n", key, util.ToIP(key), timestamp, unixtime.String())
	}

	client, err := olric.NewClusterClient([]string{fmt.Sprintf("%s:3320", discovery.ManagementInterface.PrimaryAddress)})
	if err != nil {
		return err
	}

	for _, mapName := range []string{controller.DMAP_RESOLVED_HOSTS, controller.DMAP_PKT_TRACK} {
		dmap, err := client.NewDMap(mapName)
		if err != nil {
			return err
		}
		mapIt, err := dmap.Scan(context.Background(), olric.Count(500), olric.Match(".*"))
		if err != nil {
			return err
		}
		fmt.Println("\n==============")
		fmt.Println("olric:" + mapName)
		fmt.Println("--------------")
		for mapIt.Next() {
			key := mapIt.Key()
			res, err := dmap.Get(context.Background(), key)
			if err != nil {
				logger.Error(err, "unable to get map entry")
			}
			str, err := res.String()
			if err != nil {
				fmt.Printf("%s -> %s", key, str)
			}
			i64, err := res.Int64()
			if err == nil {
				// likely a unix nanosecond timestamp
				if i64 > 1690029740975818807 {
					ts := time.Unix(0, i64)
					fmt.Printf("%s -> %s\n", key, ts.String())
				} else {
					fmt.Printf("%s -> %d\n", key, i64)
				}
			}
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
