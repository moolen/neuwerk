package ruleset

import (
	"net"
	"regexp"

	"github.com/moolen/neuwerk/pkg/log"
	"github.com/moolen/neuwerk/pkg/matchpattern"
)

var (
	logger = log.DefaultLogger.WithName("ruleset")
)

type RuleProvider interface {
	Get() *RuleSet
}

type RuleSet struct {
	Networks []Network `json:"networks"`
}

type Network struct {
	Name     string     `json:"name"`
	CIDR     CIDRString `json:"cidr"`
	Policies []Policy   `json:"policies"`
}

type Policy struct {
	Hostname string `json:"hostname"`
	Regexp   *regexp.Regexp
	Ports    []uint16 `json:"ports"`
	IP       string   `json:"ip"`
}

type CIDRString struct {
	net.IPNet
}

func (ip *CIDRString) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var strVal string
	err := unmarshal(&strVal)
	if err != nil {
		return err
	}
	_, cidr, err := net.ParseCIDR(strVal)
	ip.IP = cidr.IP
	ip.Mask = cidr.Mask
	return err
}

func (r *RuleSet) Prepare() error {
	for i, net := range r.Networks {
		for j, pol := range net.Policies {
			var err error
			if pol.Hostname == "" {
				continue
			}
			logger.Info("compiling regexp", "hostname", pol.Hostname)
			r.Networks[i].Policies[j].Regexp, err = matchpattern.Validate(pol.Hostname)
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
			logger.V(4).Info("trying match", "policy", p, "hostname", hostname)
			if p.Regexp != nil && p.Regexp.MatchString(hostname) {
				return true
			}
		}
	}
	return false
}
