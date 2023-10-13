package dnsproxy

import (
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/moolen/neuwerk/pkg/cache"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/moolen/neuwerk/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
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
	listenHostPort string,
	upstreamSDNServer string,
	dnsCache cache.Cache,
	allowedFunc AllowedFunc,
	observeFunc ObserveFunc) (*DNSProxy, error) {
	addrPort, err := netip.ParseAddrPort(listenHostPort)
	if err != nil {
		return nil, err
	}
	logger.Info("creating dnsproxy server", "addrPort", addrPort.String())
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addrPort))
	if err != nil {
		return nil, err
	}
	p := &DNSProxy{
		dnsCache:          dnsCache,
		upstreamSDNServer: upstreamSDNServer,
		allowedFunc:       allowedFunc,
		observeFunc:       observeFunc,
	}

	// TODO: implement tcp server
	p.UDPServer = &dns.Server{
		PacketConn: pc,
		Addr:       listenHostPort,
		Net:        "udp",
		Handler:    p,
	}

	return p, nil
}

func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, msg *dns.Msg) {
	resultCode := metrics.ResultCodeError
	start := time.Now()
	defer func() {
		metrics.DNSRequestDuration.With(prometheus.Labels{
			metrics.ResultLabel: resultCode,
		}).Observe(float64(time.Since(start).Seconds()))
	}()

	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		logger.Error(err, "unable to split source host/port")
		return
	}
	logger.Info("processing dns query", "client", w.RemoteAddr().String(), "msg", msg, "localAddr", w.LocalAddr().String())

	hostAddr := net.ParseIP(host)
	for _, q := range msg.Question {
		if !p.allowedFunc(hostAddr.To4(), q.Name) {
			logger.V(1).Info("rejecting traffic based on policy", "hostname", q.Name)
			metrics.RejectedDNSQueryCount.With(prometheus.Labels{}).Inc()
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
	resultCode = metrics.ResultCodeOK
}

func (p *DNSProxy) LookupWithCache(msg *dns.Msg) (*dns.Msg, error) {
	// TODO: lookup & update cache
	resultCode := metrics.ResultCodeOK
	start := time.Now()
	defer func() {
		metrics.DNSUpstreamDuration.With(prometheus.Labels{
			metrics.ResultLabel: resultCode,
		}).Observe(float64(time.Since(start).Seconds()))
	}()
	res, err := p.Lookup(msg)
	if err != nil {
		resultCode = metrics.ResultCodeError
	}
	return res, err
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
