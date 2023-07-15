/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	// nolint
	"github.com/moolen/neuwerk/pkg/integration/aws"
	. "github.com/onsi/ginkgo/v2"
	"github.com/vishvananda/netlink"

	// nolint
	. "github.com/onsi/gomega"
)

type ProcSetting struct {
	Path  string
	Value string
}

var (
	discovery      *aws.DiscoveryOutput
	httpClient     *http.Client
	httpsOnlyHosts = []string{"example.com", "github.com"}
	blockedhosts   = []string{"facebook.com"}
)

var _ = SynchronizedBeforeSuite(func() []byte {
	vpcResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, "10.0.0.2:53")
		},
	}

	var err error
	GinkgoLogr.Info("autodiscover aws context")
	discovery, err = aws.Discover(context.Background())
	if err != nil {
		Fail(err.Error())
	}

	// set arp cache/gc times to recover fast from vip failover
	GinkgoLogr.Info("modifying procfs settings")
	for _, setting := range []ProcSetting{
		{Path: "10", Value: "/proc/sys/net/ipv4/neigh/default/gc_stale_time"},
		{Path: "5000", Value: "/proc/sys/net/ipv4/neigh/default/base_reachable_time_ms"},
		{Path: "15", Value: "/proc/sys/net/ipv4/route/gc_interval"},
		{Path: "60", Value: "/proc/sys/net/ipv4/route/gc_timeout"},
	} {
		err := os.WriteFile(setting.Path, []byte(setting.Value), os.ModePerm)
		if err != nil {
			Fail(err.Error())
		}
	}

	var lnk netlink.Link
	links, err := netlink.LinkList()
	if err != nil {
		Fail(err.Error())
	}
	for _, link := range links {
		if link.Attrs().Name == "lo" {
			continue
		}
		lnk = link
	}

	hosts := append(httpsOnlyHosts, blockedhosts...)
	for _, host := range hosts {
		addrs, err := vpcResolver.LookupIP(context.Background(), "ip4", host)
		if err != nil {
			Fail(err.Error())
		}
		for _, addr := range addrs {
			GinkgoLogr.Info("replacing netlink", "iface", lnk.Attrs().Name, "addr", addr, "via", discovery.VIPAddress)
			if addr.To4() == nil {
				continue
			}
			err = netlink.RouteReplace(&netlink.Route{
				LinkIndex: lnk.Attrs().Index,
				Dst: &net.IPNet{
					IP:   addr,
					Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0xff),
				},
				Gw: net.ParseIP(discovery.VIPAddress),
			})
			if err != nil {
				Fail(err.Error())
			}
		}
	}

	if err != nil {
		Fail(err.Error())
	}

	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(5000) * time.Millisecond,
				}
				return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", discovery.VIPAddress))
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	http.DefaultTransport.(*http.Transport).DialContext = dialContext
	httpClient = &http.Client{
		Timeout: time.Second * 2,
	}

	return nil
}, func([]byte) {
	// noop
})

func TestE2E(t *testing.T) {
	NewWithT(t)
	RegisterFailHandler(Fail)
	RunSpecs(t, "e2e suite", Label("e2e"))
}
