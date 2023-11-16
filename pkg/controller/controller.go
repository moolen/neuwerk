package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
	"github.com/cilium/ebpf"
	"github.com/moolen/neuwerk/pkg/bpf"
	"github.com/moolen/neuwerk/pkg/cache"
	"github.com/moolen/neuwerk/pkg/cache/memory"
	"github.com/moolen/neuwerk/pkg/dnsproxy"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/moolen/neuwerk/pkg/metrics"
	"github.com/moolen/neuwerk/pkg/ruleset"
	"github.com/moolen/neuwerk/pkg/util"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	logger = log.DefaultLogger
)

const (
	MaxNetworks         = 1024
	CHANNEL_OBSERVE_DNS = "observe-dns"
	CHANNEL_GC_PKT_MAP  = "gc-pktmap"
	DMAP_RESOLVED_HOSTS = "resolved-hosts"
	DMAP_PKT_TRACK      = "pkt-track"
)

type Controller struct {
	ctx          context.Context
	bpffs        string
	coll         *bpf.Collection
	cache        cache.Cache
	dnsproxy     *dnsproxy.DNSProxy
	ruleProvider ruleset.RuleProvider
	integration  string

	mgmtAddr    string
	ingressAddr string

	olric                     olric.Client
	peers                     []string
	dbBindPort                int
	mgmtPort                  int
	resolvedHosts             olric.DMap
	pktTrack                  olric.DMap
	pubsub                    *olric.PubSub
	coordinatorReconcilerFunc func(ctx context.Context, isCoordinator bool) error
}

type ControllerConfig struct {
	Integration string
	// Name of the neuwerk cluster
	ClusterName string
	// Name of the target device where packets should be redirected to
	// this is the egress device.
	EgressDeviceName    string
	IngressDeviceName   string
	BPFFS               string
	DNSListenHostPort   string
	DNSUpstreamHostPort string
	Peers               []string

	ManagementAddress string
	MgmtPort          int
	DBBindPort        int
	IngressAddress    string

	RuleProvider              ruleset.RuleProvider
	CoordinatorReconcilerFunc func(ctx context.Context, isCoordinator bool) error
}

func New(ctx context.Context, opts *ControllerConfig) (*Controller, error) {
	var err error
	logger.Info("applying controller options", "mgmt_addr", opts.ManagementAddress, "mgmt_port", opts.MgmtPort)
	c := &Controller{
		ctx:                       ctx,
		integration:               opts.Integration,
		ruleProvider:              opts.RuleProvider,
		bpffs:                     opts.BPFFS,
		mgmtAddr:                  opts.ManagementAddress,
		mgmtPort:                  opts.MgmtPort,
		ingressAddr:               opts.IngressAddress,
		peers:                     opts.Peers,
		dbBindPort:                opts.DBBindPort,
		coordinatorReconcilerFunc: opts.CoordinatorReconcilerFunc,
	}
	err = c.startOlric()
	if err != nil {
		return nil, fmt.Errorf("unable to start olric: %w", err)
	}

	err = c.startCoordinator()
	if err != nil {
		return nil, fmt.Errorf("unable to start coordinator: %w", err)
	}
	c.coll, err = bpf.Load(opts.BPFFS, opts.IngressDeviceName, opts.EgressDeviceName, c.ingressAddr, opts.DNSListenHostPort)
	if err != nil {
		return nil, fmt.Errorf("unable to load bpf: %w", err)
	}

	// reset map data because we want to start from scratch when we reboot
	logger.Info("resetting ip/port policy data")
	it := c.coll.IPPortPolicies.Iterate()
	var idx uint32
	var mapID uint32
	for it.Next(&idx, &mapID) {
		polMap, err := ebpf.NewMapFromID(ebpf.MapID(mapID))
		if err != nil {
			return nil, fmt.Errorf("unable to construct map from id: %w", err)
		}
		err = polMap.Close()
		if err != nil {
			return nil, fmt.Errorf("unable to reset polMap: %w", err)
		}
	}

	err = c.coll.Attach()
	if err != nil {
		return nil, fmt.Errorf("unable to attach bpf prog: %w", err)
	}

	metrics.InitializeCollector(c.mgmtAddr, c.coll.MetricsMap)

	logger.Info("creating dnscache")
	c.cache, err = memory.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to create memory cache: %w", err)
	}
	c.resolvedHosts, err = c.olric.NewDMap(DMAP_RESOLVED_HOSTS)
	if err != nil {
		logger.Error(err, "unable to create new dmap client", "dmap", DMAP_RESOLVED_HOSTS)
		return nil, err
	}
	c.pktTrack, err = c.olric.NewDMap(DMAP_PKT_TRACK)
	if err != nil {
		logger.Error(err, "unable to create new dmap client", "dmap", DMAP_PKT_TRACK)
		return nil, err
	}
	c.dnsproxy, err = dnsproxy.New(opts.DNSListenHostPort, opts.DNSUpstreamHostPort, c.cache, c.VerifyHostname, c.observeDNS)
	if err != nil {
		return nil, fmt.Errorf("unable to create dnsproxy: %w", err)
	}
	c.dnsproxy.Start()

	// reconcile in regular intervals
	go func() {
		t := time.NewTicker(time.Second * 10)
		defer t.Stop()

		for {
			err := c.reconcileMaps()
			if err != nil {
				logger.Error(err, "unable to reconcile maps")
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				continue
			}
		}
	}()

	go c.startGCLoop()

	return c, nil
}

func (c *Controller) observeDNS(op *dnsproxy.ObservePayload) {
	key := getOPKey(op)
	res, err := c.resolvedHosts.Get(context.Background(), key)
	if err != nil && !errors.Is(err, olric.ErrKeyNotFound) {
		logger.Error(err, "unable to lookup resolved hosts")
		return
	}
	// only publish this OP if this is the first time we see it
	if res != nil {
		logger.Info("skipping known address")
		return
	}
	bt, err := json.Marshal(op)
	if err != nil {
		logger.Error(err, "unable to marshal observe payload")
		return
	}
	logger.Info("storing op", "op", string(bt))
	_, err = c.pubsub.Publish(context.Background(), CHANNEL_OBSERVE_DNS, string(bt))
	if err != nil {
		logger.Error(err, "unable to publish event", "channel", CHANNEL_OBSERVE_DNS)
		return
	}

	logger.Info("storing new value", "key", key)
	err = c.resolvedHosts.Put(context.Background(), key, time.Now().UnixNano())
	if err != nil {
		logger.Error(err, "unable to update stored value", "key", key)
		return
	}
}

func getOPKey(op *dnsproxy.ObservePayload) string {
	return op.Name + "$" + op.Address.String()
}

func (c *Controller) VerifyHostname(sourceAddr net.IP, host string) bool {
	verdict := c.ruleProvider.Get().HostAllowed(sourceAddr, host)
	// TODO: we probably shouldn't look up bpf maps in the hot path
	if setting, _ := c.coll.GetSetting(bpf.SETTING_AUDIT_MODE); setting == bpf.SETTING_ENABLED {
		return true
	}
	return verdict
}

func (c *Controller) updateMapHostname(op *dnsproxy.ObservePayload) {
	logger.Info("observing DNS response", "name", op.Name, "address", op.Address.String())
	for i, net := range c.ruleProvider.Get().Networks {
		for _, pol := range net.Policies {
			if pol.Regexp != nil && pol.Regexp.MatchString(op.Name) {
				logger.Info("updating network policy", "policy", pol, "op", op)
				var innerID ebpf.MapID
				err := c.coll.IPPortPolicies.Lookup(uint32(i), &innerID)
				if err != nil {
					logger.Error(err, "unable to lookup inner network policy id")
					continue
				}
				m, err := ebpf.NewMapFromID(innerID)
				if err != nil {
					logger.Error(err, "unable to create inner map")
					continue
				}
				for _, port := range pol.Ports {
					pk := &bpf.PolicyKey{
						UpstreamAddr: util.IPToUint(op.Address),
						UpstreamPort: util.ToNetBytes16(port),
					}
					logger.Info("updating network policy", "addr", op.Address, "net_addr", util.IPToUint(op.Address), "port", port, "net_port", util.ToHost16(port))
					err = m.Put(pk, uint32(1))
					if err != nil {
						logger.Error(err, "unable to update network policy")
						continue
					}
				}
			}
		}
	}
}

var InnerPolicyMap = &ebpf.MapSpec{
	Name:       "network_policy",
	Type:       ebpf.Hash,
	KeySize:    8,
	ValueSize:  4,
	MaxEntries: 65535,
}

func (c *Controller) reconcileMaps() error {
	start := time.Now()
	resultCode := metrics.ResultCodeError
	defer func() {
		metrics.BPFReconcileMapsDuration.With(prometheus.Labels{
			metrics.ResultLabel: resultCode,
		}).Observe(time.Since(start).Seconds())
	}()
	logger.Info("reconciling maps")
	for i := 0; i < MaxNetworks; i++ {
		if i < len(c.ruleProvider.Get().Networks) {
			// update cidr map
			network := c.ruleProvider.Get().Networks[i]
			val := &bpf.NetworkCIDR{
				Addr: util.IPToUint(network.CIDR.IP),
				Mask: util.MaskToUint(network.CIDR.Mask),
			}
			err := c.coll.NetworkCIDRs.Put(uint32(i), val)
			if err != nil {
				return fmt.Errorf("unable to put network cidrs: %w", err)
			}

			// update policy map
			m, err := ebpf.NewMap(InnerPolicyMap)
			if err != nil {
				return fmt.Errorf("unable to create inner map: %w", err)
			}
			defer m.Close()
			err = c.coll.IPPortPolicies.Put(uint32(i), uint32(m.FD()))
			if err != nil {
				return fmt.Errorf("unable to put inner network policy: %w", err)
			}

			// reconcile policy map data
			for _, pol := range network.Policies {
				var addrs []string

				// find all entries matching this hostname
				if pol.Hostname != "" {
					// the regexp string terminates with a '$', we replace it with '.*' to get all IPs matching this hostname
					matcher := pol.Regexp.String()
					matcher = matcher[0:len(matcher)-1] + ".*"
					logger.V(2).Info("scanning for host", "hostname", pol.Hostname, "match", matcher)
					it, err := c.resolvedHosts.Scan(context.Background(), olric.Match(matcher))
					if err != nil {
						logger.Error(err, "unable to get iterator")
						continue
					}
					defer it.Close()
					for it.Next() {
						key := it.Key()
						logger.V(3).Info("processing resolved host", "key", key)
						lastIdx := strings.LastIndex(key, "$")
						if lastIdx == -1 {
							continue
						}
						addrs = append(addrs, key[lastIdx+1:])
					}
				} else if pol.IP != "" {
					// uses statically confiured addr
					addrs = []string{pol.IP}
				}
				logger.V(2).Info("reconciling policy map data", "policy", pol, "addrs", addrs)
				for _, addr := range addrs {
					for _, port := range pol.Ports {
						pk := &bpf.PolicyKey{
							UpstreamAddr: util.IPToUint(net.ParseIP(addr)),
							UpstreamPort: util.ToNetBytes16(port),
						}
						logger.V(3).Info("adding static egress ips", "network", network.Name, "ip", addr, "port", port)
						err = m.Put(pk, uint32(1))
						if err != nil {
							logger.Error(err, "unable to add network policy", "network", network.Name, "ip", addr)
						}
					}
				}
			}
		} else {
			// delete stale cidr entries
			var emptyCidr bpf.NetworkCIDR
			err := c.coll.NetworkCIDRs.Put(uint32(i), emptyCidr)
			if err != nil {
				return fmt.Errorf("unable to reset network cidrs %w", err)
			}
			// delete stale policy entries
			err = c.coll.IPPortPolicies.Delete(uint32(i))
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("unable to delete network policies: %w", err)
			}
		}
	}

	resultCode = metrics.ResultCodeOK
	return nil
}

func (c *Controller) startOlric() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	cfg := config.New("lan")
	cfg.Peers = c.peers
	cfg.BindAddr = c.mgmtAddr
	cfg.BindPort = c.dbBindPort
	cfg.JoinRetryInterval = time.Second * 10
	cfg.MaxJoinAttempts = 30
	cfg.MemberlistConfig.AdvertiseAddr = c.mgmtAddr
	cfg.MemberlistConfig.AdvertisePort = c.mgmtPort
	cfg.MemberlistConfig.BindAddr = c.mgmtAddr
	cfg.MemberlistConfig.BindPort = c.mgmtPort
	cfg.EnableClusterEventsChannel = true
	cfg.Started = func() {
		logger.Info("[INFO] Olric is ready to accept connections")
		cancel()
	}
	logger.Info("starting olric",
		"peers", cfg.Peers,
		"bind", net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort)),
		"memberlist:advertise", net.JoinHostPort(cfg.MemberlistConfig.AdvertiseAddr, strconv.Itoa(cfg.MemberlistConfig.AdvertisePort)),
		"memberlist:bind", net.JoinHostPort(cfg.MemberlistConfig.BindAddr, strconv.Itoa(cfg.MemberlistConfig.BindPort)),
	)
	db, err := olric.New(cfg)
	if err != nil {
		return err
	}
	go func() {
		err = db.Start()
		if err != nil {
			logger.Error(err, "olric.Start returned an error")
			cancel()
		}
	}()
	<-ctx.Done()

	c.olric = db.NewEmbeddedClient()
	c.pubsub, err = c.olric.NewPubSub(olric.ToAddress(cfg.MemberlistConfig.Name))
	if err != nil {
		return err
	}
	ctx = context.Background()
	ps := c.pubsub.Subscribe(ctx, CHANNEL_OBSERVE_DNS)
	go func() {
		logger.Info("starting subscribe handler", "channel", CHANNEL_OBSERVE_DNS)
		for {
			select {
			case <-c.ctx.Done():
				return
			case msg := <-ps.Channel():
				logger.V(2).Info("received publish event", "channel", msg.Channel, "payload", msg.Payload)
				var op dnsproxy.ObservePayload
				err := json.Unmarshal([]byte(msg.Payload), &op)
				if err != nil {
					logger.Error(err, "unable to unmarshal payload into ObservePayload", "channel", CHANNEL_OBSERVE_DNS, "payload", msg.Payload)
					continue
				}
				c.updateMapHostname(&op)
			}
		}
	}()

	gcps := c.pubsub.Subscribe(ctx, CHANNEL_GC_PKT_MAP)
	go func() {
		logger.Info("starting gc handler", "channel", CHANNEL_GC_PKT_MAP)
		for {
			select {
			case <-c.ctx.Done():
				return
			case msg := <-gcps.Channel():
				logger.V(2).Info("received publish event", "channel", msg.Channel, "payload", msg.Payload)
				err = c.gcBPFMaps(msg.Payload)
				if err != nil {
					logger.Error(err, "unable to gc bpf maps")
				}
			}
		}
	}()

	return nil
}

func (c *Controller) Close() {
	err := c.coll.Close()
	if err != nil {
		logger.Error(err, "unable to close bpf coll")
	}
	c.cache.Close()
	c.dnsproxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err = c.olric.Close(ctx)
	if err != nil {
		logger.Error(err, "unable to close olric client")
	}
}
