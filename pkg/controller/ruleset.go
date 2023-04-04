package controller

import (
	"net"
	"regexp"

	"github.com/moolen/neuwerk/pkg/matchpattern"
)

type RuleSet struct {
	Networks []Network
}

type Network struct {
	Name     string
	CIDR     net.IPNet
	Policies []Policy
}

type Policy struct {
	Hostname string
	regexp   *regexp.Regexp
	Ports    []uint16
	IP       string
}

var TestRules = &RuleSet{
	Networks: []Network{

		{
			Name: "test",
			CIDR: net.IPNet{
				IP:   net.IP{127, 0, 0, 1},
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			Policies: []Policy{
				{
					Hostname: "*.x.pipedream.net",
					Ports:    []uint16{443},
				},
				{
					Hostname: "form3.tech.",
					Ports:    []uint16{443},
				},
				{
					Hostname: "example.com.",
					Ports:    []uint16{443, 80},
				},
				{
					Hostname: "github.com.",
					Ports:    []uint16{443},
				},
			},
		},
		{
			Name: "test",
			CIDR: net.IPNet{
				IP:   net.IP{192, 168, 0, 0},
				Mask: net.IPv4Mask(255, 255, 0, 0),
			},
			Policies: []Policy{
				{
					Hostname: "*.x.pipedream.net",
					Ports:    []uint16{443},
				},
				{
					Hostname: "example.com.",
					Ports:    []uint16{443, 80},
				},
				{
					Hostname: "github.com.",
					Ports:    []uint16{443},
				},
				{
					IP:    "192.168.178.35",
					Ports: []uint16{3322, 3320},
				},
				{
					IP:    "192.168.178.36",
					Ports: []uint16{3322, 3320},
				},
				{
					IP:    "192.168.178.37",
					Ports: []uint16{3322, 3320},
				},
			},
		},
	},
}

func init() {
	err := TestRules.Prepare()
	if err != nil {
		panic(err)
	}
}

func (r *RuleSet) Prepare() error {
	for i, net := range r.Networks {
		for j, pol := range net.Policies {
			var err error
			if pol.Hostname == "" {
				continue
			}
			r.Networks[i].Policies[j].regexp, err = matchpattern.Validate(pol.Hostname)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *RuleSet) HostAllowed(sourceAddr net.IP, hostname string) bool {
	for _, network := range r.Networks {
		if !network.CIDR.Contains(sourceAddr) {
			continue
		}
		for _, p := range network.Policies {
			logger.Info("trying match", "p.Hostname", p.Hostname, "re", p.regexp.String(), "hostname", hostname)
			if p.regexp != nil && p.regexp.MatchString(hostname) {
				return true
			}
		}
	}
	return false
}
