// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfAuditEvent struct {
	SourceAddr uint32
	DestAddr   uint32
	SourcePort uint16
	DestPort   uint16
	Proto      uint8
	Unused0    uint8
	Unused1    uint16
}

type bpfNetworkCidr struct {
	Addr uint32
	Mask uint32
}

type bpfPolicyKey struct {
	UpstreamAddr uint32
	UpstreamPort uint16
	Unused       uint16
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	Ingress *ebpf.ProgramSpec `ebpf:"ingress"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	AuditRingbuf   *ebpf.MapSpec `ebpf:"audit_ringbuf"`
	IpPortPolicies *ebpf.MapSpec `ebpf:"ip_port_policies"`
	Metrics        *ebpf.MapSpec `ebpf:"metrics"`
	NetworkCidrs   *ebpf.MapSpec `ebpf:"network_cidrs"`
	PktTrack       *ebpf.MapSpec `ebpf:"pkt_track"`
	Settings       *ebpf.MapSpec `ebpf:"settings"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	AuditRingbuf   *ebpf.Map `ebpf:"audit_ringbuf"`
	IpPortPolicies *ebpf.Map `ebpf:"ip_port_policies"`
	Metrics        *ebpf.Map `ebpf:"metrics"`
	NetworkCidrs   *ebpf.Map `ebpf:"network_cidrs"`
	PktTrack       *ebpf.Map `ebpf:"pkt_track"`
	Settings       *ebpf.Map `ebpf:"settings"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.AuditRingbuf,
		m.IpPortPolicies,
		m.Metrics,
		m.NetworkCidrs,
		m.PktTrack,
		m.Settings,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	Ingress *ebpf.Program `ebpf:"ingress"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.Ingress,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
