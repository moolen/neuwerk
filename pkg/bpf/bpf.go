package bpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/moolen/neuwerk/pkg/util"
	"github.com/vishvananda/netlink"
)

type Collection struct {
	IngressProg *ebpf.Program

	NetworkCIDRs    *ebpf.Map
	IPPortPolicies  *ebpf.Map
	PolicyConfigMap *ebpf.Map
	PktTrack        *ebpf.Map
	MetricsMap      *ebpf.Map
	AuditEvents     *ebpf.Map
	SettingsMap     *ebpf.Map

	ingressDeviceName string
}

type NetworkCIDR bpfNetworkCidr
type PolicyKey bpfPolicyKey
type AuditEvent bpfAuditEvent

const (
	SETTING_ENABLE_MONITOR uint32 = 1
	SETTING_AUDIT_MODE     uint32 = 2
	SETTING_ENABLED        uint32 = 1
	SETTING_DISABLED       uint32 = 0
)

var namedSettings = map[string]uint32{
	"enable-monitor": SETTING_ENABLE_MONITOR,
	"audit-mode":     SETTING_AUDIT_MODE,
}

var (
	// Name of the directory in /sys/fs/bpf that holds the pinned maps/progs
	BPFMountDir = "neuwerk"
	logger      = log.DefaultLogger.WithName("bpf").V(1)
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type policy_key -type network_cidr -type audit_event bpf ./c/ingress.c -- -I./c/headers
func Load(bpffs, ingressDeviceName, egressDeviceName, ingressAddr, dnsListenHostPort string) (*Collection, error) {
	pinPath := filepath.Join(bpffs, BPFMountDir)
	logger.Info("loading bpf", "pin-path", pinPath)
	err := os.MkdirAll(pinPath, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create bpf fs subpath %q: %+v", pinPath, err)
	}

	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}

	err = rewriteConstants(spec, egressDeviceName, ingressAddr, dnsListenHostPort)
	if err != nil {
		return nil, err
	}

	logger.Info("loading eBPF maps")
	err = spec.LoadAndAssign(&objs.bpfMaps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	})
	if err != nil {
		return nil, err
	}
	logger.Info("loading eBPF programs")
	err = spec.LoadAndAssign(&objs.bpfPrograms, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ebpf.ProgramOptions{
			LogSize: 1024 * 1024,
		},
	})
	ve := &ebpf.VerifierError{}
	if errors.As(err, &ve) {
		fmt.Println(strings.Join(ve.Log, "\n"))
		logger.Error(err, "unable to load bpf prog")
	}
	if err != nil {
		return nil, err
	}
	return &Collection{
		IngressProg:       objs.bpfPrograms.Ingress,
		NetworkCIDRs:      objs.bpfMaps.NetworkCidrs,
		IPPortPolicies:    objs.bpfMaps.IpPortPolicies,
		PktTrack:          objs.bpfMaps.PktTrack,
		MetricsMap:        objs.bpfMaps.Metrics,
		AuditEvents:       objs.bpfMaps.AuditRingbuf,
		SettingsMap:       objs.bpfMaps.Settings,
		ingressDeviceName: ingressDeviceName,
	}, nil
}

// rewrites constants in bpf spec to store static data
// see `static volatile const` in `ingress.c`
func rewriteConstants(spec *ebpf.CollectionSpec, targetRedirectDeviceName, ingressAddr, dnsListenHostPort string) error {
	// get ingress device index
	nl, err := netlink.LinkByName(targetRedirectDeviceName)
	if err != nil {
		return err
	}
	idx := uint32(nl.Attrs().Index)
	logger.Info("rewriting constants", "target-redirect-device", targetRedirectDeviceName, "ingress-addr", ingressAddr, "dnslistenhostport", dnsListenHostPort, "bpf-redirect-device-index", idx)

	// get ingress address
	ingAddr := net.ParseIP(ingressAddr)
	if err != nil {
		return fmt.Errorf("unable to parse ingress addr %s", ingressAddr)
	}

	// get dns listen port
	_, dnsPortStr, err := net.SplitHostPort(dnsListenHostPort)
	if err != nil {
		return err
	}
	dnsPort, err := strconv.Atoi(dnsPortStr)
	if err != nil {
		return err
	}

	return spec.RewriteConstants(map[string]interface{}{
		"net_redir_device": idx,
		"ingress_addr":     util.IPToUint(ingAddr),
		"dns_listen_port":  util.ToNetBytes16(uint16(dnsPort)),
	})
}

func (coll *Collection) Attach() error {
	logger.Info("attaching to device", "device", coll.ingressDeviceName)
	err := attachProgram(coll.ingressDeviceName, coll.IngressProg, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}
	return nil
}

func (coll *Collection) ApplySetting(key uint32, value uint32) error {
	return coll.SettingsMap.Put(key, value)
}

func (coll *Collection) ApplyNamedSetting(name string, value uint32) error {
	key, ok := namedSettings[name]
	if !ok {
		return fmt.Errorf("setting %q does not exist", name)
	}
	return coll.SettingsMap.Put(key, value)
}

func (coll *Collection) GetSetting(key uint32) (uint32, error) {
	var val uint32
	err := coll.SettingsMap.Lookup(key, &val)
	return val, err
}

func (coll *Collection) GetNamedSetting(name string) (uint32, error) {
	key, ok := namedSettings[name]
	if !ok {
		return 0, fmt.Errorf("setting %q does not exist", name)
	}
	var val uint32
	err := coll.SettingsMap.Lookup(key, &val)
	return val, err
}

func (coll *Collection) Close() error {
	return detachProgram(coll.ingressDeviceName, coll.IngressProg, netlink.HANDLE_MIN_INGRESS)
}
