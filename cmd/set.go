package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/moolen/neuwerk/pkg/bpf"
	"github.com/moolen/neuwerk/pkg/integration/aws"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set",
	Short: "apply runtime settings to neuwerk",
	Long:  ``,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		setting := args[0]
		value, err := strconv.Atoi(args[1])
		if err != nil {
			logger.Info("invalid argument %q: expected int", args[1])
			os.Exit(1)
		}
		err = applySettings(bpffs, setting, uint32(value))
		if err != nil {
			logger.Error(err, "unable to apply setting")
			os.Exit(1)
		}
		logger.Info("applied setting")
	},
}

func applySettings(bpffs string, setting string, value uint32) error {
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
	return coll.ApplyNamedSetting(setting, value)
}

func init() {
	rootCmd.AddCommand(setCmd)
}
