package dnsproxy

import (
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/moolen/neuwerk/pkg/cache"
	"github.com/moolen/neuwerk/pkg/log"
)

type DNSProxy struct {
	UDPServer         *dns.Server
	dnsCache          cache.Cache
	upstreamSDNServer string
	allowedFunc       AllowedFunc
	observeFunc       ObserveFunc
}

var logger = log.DefaultLogger.WithName("dnsproxy").V(1)

type AllowedFunc func(sourceAddr net.IP, host string) bool

type ObservePayload struct {
	Name    string `json:"name"`
	Address net.IP `json:"address"`
	TTL     uint32 `json:"ttl"`
}
type ObserveFunc func(*ObservePayload)

func New(
	listenAddr string,
	upstreamSDNServer string,
	dnsCache cache.Cache,
	allowedFunc AllowedFunc,
	observeFunc ObserveFunc) (*DNSProxy, error) {
	logger.Info("creating dnsproxy server", "listen", listenAddr)
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(
		listenAddr,
	)))
	if err != nil {
		return nil, err
	}
	p := &DNSProxy{
		dnsCache:          dnsCache,
		upstreamSDNServer: upstreamSDNServer,
		allowedFunc:       allowedFunc,
		observeFunc:       observeFunc,
	}

	p.UDPServer = &dns.Server{
		PacketConn: pc,
		Addr:       listenAddr,
		Net:        "udp",
		Handler:    p,
	}

	return p, nil
}

func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, msg *dns.Msg) {
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		logger.Error(err, "unable to split source host/port")
		return
	}
	logger.Info("processing dns query", "client", host, "msg", msg)

	hostAddr := net.ParseIP(host)
	for _, q := range msg.Question {
		if !p.allowedFunc(hostAddr.To4(), q.Name) {
			logger.V(1).Info("rejecting traffic based on policy", "hostname", q.Name)
			cpy := &dns.Msg{}
			cpy.SetRcode(msg, dns.RcodeNameError)
			w.WriteMsg(cpy)
			return
		}
	}

	origId := msg.Id
	msg.Id = dns.Id()
	res, err := p.LookupWithCache(msg)
	if err != nil {
		logger.Error(err, "unable to lookup hostname")
		return
	}

	for i := range res.Answer {
		arec, ok := res.Answer[i].(*dns.A)
		if !ok {
			continue
		}
		p.observeFunc(&ObservePayload{
			Name:    arec.Hdr.Name,
			Address: arec.A,
			TTL:     arec.Hdr.Ttl,
		})
	}

	res.Id = origId
	msg.Id = origId
	logger.Info("writing downstream response", "res", res)
	err = w.WriteMsg(res)
	if err != nil {
		logger.Error(err, "unable to write msg to downstream connection")
	}
}

func (p *DNSProxy) LookupWithCache(msg *dns.Msg) (*dns.Msg, error) {
	// TODO: lookup & update cache
	return p.Lookup(msg)
}

func (p *DNSProxy) Lookup(msg *dns.Msg) (*dns.Msg, error) {
	cl := dns.Client{
		Net:            "udp",
		Timeout:        time.Second * 2,
		SingleInflight: false,
	}
	res, _, err := cl.Exchange(msg, p.upstreamSDNServer)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (p *DNSProxy) Start() {
	logger.Info("starting dnsproxy")
	go func() {
		err := p.UDPServer.ActivateAndServe()
		if err != nil {
			logger.Error(err, "unable to start dnsproxy server")
		}
	}()
}

func (p *DNSProxy) Close() {}
