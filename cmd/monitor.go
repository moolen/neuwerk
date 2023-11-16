package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/moolen/neuwerk/pkg/bpf"
	"github.com/moolen/neuwerk/pkg/integration/aws"
	"github.com/moolen/neuwerk/pkg/util"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := monitor(bpffs)
		if err != nil {
			logger.Error(err, "unable to monitor")
		}
	},
}

var protoMap = map[uint8]string{
	1:  "ICMP",
	4:  "IPIP",
	6:  "TCP",
	17: "UDP",
}

func monitor(bpffs string) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	discovery, err := aws.Discover(context.Background())
	if err != nil {
		return fmt.Errorf("unable to discover peers: %w", err)
	}
	coll, err := bpf.Load(bpffs, discovery.IngressInterface.DeviceName, discovery.EgressInterface.DeviceName, discovery.IngressInterface.PrimaryAddress, dnsListenHostPort)
	if err != nil {
		return err
	}
	err = coll.ApplySetting(bpf.SETTING_ENABLE_MONITOR, bpf.SETTING_ENABLED)
	if err != nil {
		return err
	}
	defer coll.ApplySetting(bpf.SETTING_ENABLE_MONITOR, bpf.SETTING_DISABLED)

	rd, err := ringbuf.NewReader(coll.AuditEvents)
	if err != nil {
		logger.Error(err, "opening ringbuf reader: %s")
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			logger.Error(err, "closing ringbuf reader")
		}
	}()

	logger.Info("Waiting for events..")
	var event bpf.AuditEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				logger.Info("Received signal, exiting..")
				return nil
			}
			logger.Error(err, "reading from reader")
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Info("parsing ringbuf event: %s", err)
			continue
		}

		// TODO: aggregate by connection
		fmt.Printf("[%s] %s:%d -> %s:%d\n", printProto(event.Proto), util.ToIP(event.SourceAddr), util.ToHost16(event.SourcePort), util.ToIP(event.DestAddr), util.ToHost16(event.DestPort))
	}
}

func printProto(proto uint8) string {
	str, ok := protoMap[proto]
	if !ok {
		return strconv.Itoa(int(proto))
	}
	return str
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
