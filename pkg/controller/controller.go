package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	"github.com/moolen/neuwerk/pkg/util"
)

var (
	logger = log.DefaultLogger
)

const (
	MaxNetworks         = 255
	CHANNEL_OBSERVE_DNS = "observe-dns"
	DMAP_RESOLVED_HOSTS = "resolved-hosts"
)

type Controller struct {
	ctx      context.Context
	bpffs    string
	coll     *bpf.Collection
	cache    cache.Cache
	dnsproxy *dnsproxy.DNSProxy

	olric                   olric.Client
	olricPeers              []string
	olricBindAddr           string
	olricBindPort           int
	memberListBindAddr      string
	memberListBindPort      int
	memberListAdvertiseAddr string
	memberListAdvertisePort int
	resolvedHosts           olric.DMap
	pubsub                  *olric.PubSub
}

type ControllerConfig struct {
	DeviceName              string
	BPFFS                   string
	DNSListenAddress        string
	DNSUpstreamAddress      string
	Peers                   []string
	DBBindAddr              string
	DBBindPort              int
	MemberListBindAddr      string
	MemberListBindPort      int
	MemberListAdvertiseAddr string
	MemberListAdvertisePort int
}

func New(ctx context.Context, opts *ControllerConfig) (*Controller, error) {
	var err error
	c := &Controller{
		ctx:                     ctx,
		bpffs:                   opts.BPFFS,
		olricPeers:              opts.Peers,
		olricBindAddr:           opts.DBBindAddr,
		olricBindPort:           opts.DBBindPort,
		memberListBindAddr:      opts.MemberListBindAddr,
		memberListBindPort:      opts.MemberListBindPort,
		memberListAdvertiseAddr: opts.MemberListAdvertiseAddr,
		memberListAdvertisePort: opts.MemberListAdvertisePort,
	}
	err = c.initializeOlric()
	if err != nil {
		return nil, fmt.Errorf("unable to start olric: %w", err)
	}
	c.coll, err = bpf.Load(opts.BPFFS)
	if err != nil {
		return nil, fmt.Errorf("unable to load bpf: %w", err)
	}
	err = c.coll.Attach(opts.DeviceName)
	if err != nil {
		return nil, fmt.Errorf("unable to attach bpf prog: %w", err)
	}

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
	c.dnsproxy, err = dnsproxy.New(opts.DNSListenAddress, opts.DNSUpstreamAddress, c.cache, c.VerifyHostname, c.observeDNS)
	if err != nil {
		return nil, fmt.Errorf("unable to create dnsproxy: %w", err)
	}
	c.dnsproxy.Start()
	err = c.reconcileMaps()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Controller) observeDNS(op *dnsproxy.ObservePayload) {
	// only publish this OP if this is the first time we see it
	key := getOPKey(op)
	res, err := c.resolvedHosts.Get(context.Background(), key)
	if err != nil && !errors.Is(err, olric.ErrKeyNotFound) {
		logger.Error(err, "unable to lookup resolved hosts")
		return
	}
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
	err = c.resolvedHosts.Put(context.Background(), key, time.Now().Unix())
	if err != nil {
		logger.Error(err, "unable to update stored value", "key", key)
		return
	}
}

func getOPKey(op *dnsproxy.ObservePayload) string {
	return op.Name + "$" + op.Address.String()
}

func (c *Controller) VerifyHostname(sourceAddr net.IP, host string) bool {
	logger.Info("verifying hostname", "host", host)
	return TestRules.HostAllowed(sourceAddr, host)
}

func (c *Controller) updateMapHostname(op *dnsproxy.ObservePayload) {
	logger.Info("observing DNS response", "name", op.Name, "address", op.Address.String())
	for i, net := range TestRules.Networks {
		for _, pol := range net.Policies {
			if pol.regexp != nil && pol.regexp.MatchString(op.Name) {
				var innerID ebpf.MapID
				err := c.coll.NetworkPolicies.Lookup(uint32(i), &innerID)
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

var innerPolicyMap = &ebpf.MapSpec{
	Name:       "network_policy",
	Type:       ebpf.Hash,
	KeySize:    8,
	ValueSize:  4,
	MaxEntries: 65535,
}

func (c *Controller) reconcileMaps() error {
	for i := 0; i < MaxNetworks; i++ {
		if i < len(TestRules.Networks) {
			// add to map
			network := TestRules.Networks[i]
			val := &bpf.NetworkCIDR{
				Addr: util.IPToUint(network.CIDR.IP),
				Mask: util.MaskToUint(network.CIDR.Mask),
			}
			err := c.coll.NetworkCIDRs.Put(uint32(i), val)
			if err != nil {
				return fmt.Errorf("unable to put network cidrs: %w", err)
			}

			m, err := ebpf.NewMap(innerPolicyMap)
			if err != nil {
				return fmt.Errorf("unable to create inner map: %w", err)
			}
			defer m.Close()
			err = c.coll.NetworkPolicies.Put(uint32(i), uint32(m.FD()))
			if err != nil {
				return fmt.Errorf("unable to put inner network policy: %w", err)
			}

			// reconcile static data
			for _, pol := range network.Policies {
				if pol.IP == "" {
					continue
				}
				for _, port := range pol.Ports {
					pk := &bpf.PolicyKey{
						UpstreamAddr: util.IPToUint(net.ParseIP(pol.IP)),
						UpstreamPort: util.ToNetBytes16(port),
					}
					logger.Info("adding static egress ips", "network", network.Name, "ip", pol.IP, "port", port)
					err = m.Put(pk, uint32(1))
					if err != nil {
						logger.Error(err, "unable to add network policy", "network", network.Name, "ip", pol.IP)
					}
				}
			}

		} else {
			// delete entries that have been removed
			var emptyCidr bpf.NetworkCIDR
			err := c.coll.NetworkCIDRs.Put(uint32(i), emptyCidr)
			if err != nil {
				return fmt.Errorf("unable to reset network cidrs %w", err)
			}
			err = c.coll.NetworkPolicies.Delete(uint32(i))
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("unable to delete network policies: %w", err)
			}
		}
	}

	logger.Info("scanning existing host entries")
	it, err := c.resolvedHosts.Scan(context.Background(), olric.Match(".*"))
	if err != nil {
		return fmt.Errorf("unable to scan resolved hosts: %w", err)
	}

	defer it.Close()
	for it.Next() {
		key := it.Key()
		logger.Info("processing resolved host", "key", key)
		lastIdx := strings.LastIndex(key, "$")
		if lastIdx == -1 {
			continue
		}
		hostname := key[:lastIdx]
		stringAddr := key[lastIdx+1:]
		addr := net.ParseIP(stringAddr)
		if addr == nil {
			logger.Error(err, "unable to parse ip", "addr", stringAddr, "key", key)
			continue
		}
		logger.Info("processing resolved hosts", "key", key, "hostname", hostname, "addr", addr.String())
		c.updateMapHostname(&dnsproxy.ObservePayload{
			Name:    hostname,
			Address: addr,
		})
	}

	return nil
}

func (c *Controller) initializeOlric() error {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.New("lan")
	cfg.Peers = c.olricPeers
	cfg.BindAddr = c.olricBindAddr
	cfg.BindPort = c.olricBindPort
	cfg.MemberlistConfig.AdvertiseAddr = c.memberListAdvertiseAddr
	cfg.MemberlistConfig.AdvertisePort = c.memberListAdvertisePort
	cfg.MemberlistConfig.BindAddr = c.memberListBindAddr
	cfg.MemberlistConfig.BindPort = c.memberListBindPort
	cfg.Started = func() {
		defer cancel()
		logger.Info("[INFO] Olric is ready to accept connections")
	}
	db, err := olric.New(cfg)
	if err != nil {
		return err
	}
	go func() {
		err = db.Start()
		if err != nil {
			logger.Error(err, "olric.Start returned an error")
		}
	}()
	<-ctx.Done()
	c.olric = db.NewEmbeddedClient()
	c.pubsub, err = c.olric.NewPubSub(olric.ToAddress(cfg.MemberlistConfig.Name))
	if err != nil {
		return err
	}

	ps := c.pubsub.Subscribe(ctx, CHANNEL_OBSERVE_DNS)
	go func() {
		logger.Info("starting subscribe handler", "channel", CHANNEL_OBSERVE_DNS)
		for {
			select {
			case <-c.ctx.Done():
				return
			case msg := <-ps.Channel():
				logger.Info("received publish event", "channel", msg.Channel, "payload", msg.Payload)
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
