package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/vishvananda/netlink"
)

type Collection struct {
	IngressProg *ebpf.Program

	NetworkCIDRs    *ebpf.Map
	NetworkPolicies *ebpf.Map
	PolicyConfigMap *ebpf.Map

	deviceName string
}

type NetworkCIDR bpfNetworkCidr
type PolicyKey bpfPolicyKey

var (
	// Name of the directory in /sys/fs/bpf that holds the pinned maps/progs
	BPFMountDir = "neuwerk"
	logger      = log.DefaultLogger.WithName("bpf").V(1)
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type policy_key -type network_cidr bpf ./c/ingress.c -- -I./c/headers
func Load(bpffs string) (*Collection, error) {
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
	err = spec.LoadAndAssign(&objs.bpfMaps, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	})
	if err != nil {
		return nil, err
	}
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
		IngressProg:     objs.bpfPrograms.Ingress,
		NetworkCIDRs:    objs.bpfMaps.NetworkCidrs,
		NetworkPolicies: objs.bpfMaps.NetworkPolicies,
	}, nil
}

func (coll *Collection) Attach(deviceName string) error {
	logger.Info("attaching to device", "device", deviceName)
	coll.deviceName = deviceName
	err := attachProgram(deviceName, coll.IngressProg, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}
	return nil
}

func (coll *Collection) Close() error {
	return detachProgram(coll.deviceName, coll.IngressProg, netlink.HANDLE_MIN_INGRESS)
}
