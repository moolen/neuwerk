package controller

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/buraksezer/olric"
	"github.com/cilium/ebpf"
	"github.com/moolen/neuwerk/pkg/bpf"
	"github.com/moolen/neuwerk/pkg/metrics"
	"github.com/moolen/neuwerk/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
)

func (c *Controller) startGCLoop() {
	// algorithm:
	// 1. every ~5m: push last-seen-packet timestamp to olric map
	//
	// 2. after 2h 30m delete stale hostname/ip data based on last-seen-packet timestamp
	//
	// Note on the timing:
	// tcp keepalive time is by default ~2h, so ideally we should see a packet every 2h
	// if we take down an instance for maintenance traffic is re-routed to another node which
	// will observe the packet.
	//
	// approx. mem stats:
	// 4byte per IPv4 address + 8byte for timestamp:
	// -> 65k hosts ~= 7.5M memory
	// -> 16M hosts ~= 200M memory
	pushTicker := time.NewTicker(time.Minute * 1)
	gcTicker := time.NewTicker(time.Minute * 1)
	keepaliveWindow := time.Minute * 3

	for {
		select {
		case <-pushTicker.C:
			ctx := context.Background()
			logger.Info("gc: push data to olric")
			it := c.coll.PktTrack.Iterate()
			var key uint32
			var timestamp int64
			for it.Next(&key, &timestamp) {
				err := c.pktTrack.Put(ctx, string(util.ToIP(key).String()), timestamp)
				if err != nil {
					logger.Error(err, "unable to push PktTrack data to olric")
					continue
				}
			}
		case <-gcTicker.C:
			logger.Info("gc: cleanup stale connection")
			err := c.gcOlricMaps(keepaliveWindow)
			if err != nil {
				logger.Error(err, "unable to cleanup stale connections")
			}
		case <-c.ctx.Done():
			return
		}

	}
}

// scans through olric PktTrack map and deletes stale entries from:
// - PktTrack DMAP
// - resolvedHosts DMAP
// and emits a event via pubsub to inform other members to
// delete the entry as well
func (c *Controller) gcOlricMaps(keepaliveWindow time.Duration) error {
	start := time.Now()
	resultCode := metrics.ResultCodeError
	defer func() {
		metrics.GCStaleDistributedState.With(prometheus.Labels{
			metrics.ResultLabel: resultCode,
		}).Observe(time.Since(start).Seconds())
	}()

	// first: get map of static IPs which should not be touched
	staticAddr := map[string]struct{}{}
	rs := c.ruleProvider.Get()
	for _, net := range rs.Networks {
		for _, pol := range net.Policies {
			if pol.IP != "" {
				staticAddr[pol.IP] = struct{}{}
			}
		}
	}

	// scan over olric PktTrack, removing expired IPs
	it, err := c.pktTrack.Scan(context.Background())
	if err != nil {
		return fmt.Errorf("unable to scan over PktTrack: %w", err)
	}
	defer it.Close()

	for it.Next() {
		key := it.Key()
		res, err := c.pktTrack.Get(context.Background(), key)
		if err != nil {
			logger.Error(err, "unable to get key", "key", key)
			continue
		}
		unixNs, err := res.Int64()
		if err != nil {
			logger.Error(err, "unexpected non-int64 value", "key", key)
			continue
		}
		lastSeen := time.Unix(0, unixNs)

		_, isStaticAddr := staticAddr[key]
		if !isStaticAddr && lastSeen.Add(keepaliveWindow).Before(time.Now().UTC()) {
			// remove connection from:
			// - PktTrack DMAP
			// - resolvedHosts DMAP
			// also emit event to inform other members about it
			_, err = c.pktTrack.Delete(context.Background(), key)
			if err != nil {
				logger.Error(err, "unable to delete PktTrack entry", "key", key)
			}

			_, err := c.pubsub.Publish(context.Background(), CHANNEL_GC_PKT_MAP, key)
			if err != nil {
				logger.Error(err, "unable to publish gc pktmap event")
			}

			it, err := c.resolvedHosts.Scan(context.Background(), olric.Match(`.*\$`+key))
			if err != nil {
				logger.Error(err, "unable to scan hostname map")
				continue
			}
			for it.Next() {
				hostnameKey := it.Key()
				_, err = c.resolvedHosts.Delete(context.Background(), hostnameKey)
				if err != nil {
					logger.Error(err, "unable to delete resolvedHosts key", "key", hostnameKey)
				}
			}
		}
	}
	resultCode = metrics.ResultCodeOK
	return nil
}

// removes the supplied addr from network policies bpf maps
// This effectively blocks all subsequent connections to that address
// until a DNS query has been made to open it up again.
func (c *Controller) gcBPFMaps(addr string) error {
	nboAddr := util.IPToUint(net.ParseIP(addr))

	// delete from PktTrack table
	err := c.coll.PktTrack.Delete(nboAddr)
	if err != nil && err != ebpf.ErrKeyNotExist {
		logger.Error(err, "unable to gc PktTrack eBPF map", "key", nboAddr, "addr", addr)
	}

	// delete from NetworkPolicy table
	// TODO: consider aggregating the ports to do direct lookups on the polMap
	//       instead of iterating over all entries
	it := c.coll.NetworkPolicies.Iterate()
	var netIdx uint32
	var polMapID uint32
	for it.Next(&netIdx, &polMapID) {
		polMap, err := ebpf.NewMapFromID(ebpf.MapID(polMapID))
		if err != nil {
			logger.Error(err, "gc: unable to construct map from id")
			continue
		}
		polIt := polMap.Iterate()
		var pk bpf.PolicyKey
		var val uint32
		for polIt.Next(&pk, &val) {
			if pk.UpstreamAddr == nboAddr {
				err = polMap.Delete(pk)
				if err != nil {
					logger.Error(err, "unable to gc key in polMap", "addr", addr, "key", pk)
				}
			}
		}
	}
	return nil
}
