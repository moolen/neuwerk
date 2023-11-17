package cmd

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	memorycache "github.com/moolen/neuwerk/pkg/cache/memory"
	"github.com/moolen/neuwerk/pkg/dnsproxy"
	"github.com/spf13/cobra"
)

var dnsproxyCmd = &cobra.Command{
	Use:   "dnsproxy",
	Short: "start only the dns proxy with a default-allow policy",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		allowAll := func(sourceAddr net.IP, host string) bool { return true }
		noopObserve := func(op *dnsproxy.ObservePayload) {}
		cache, err := memorycache.New(context.Background())
		if err != nil {
			logger.Error(err, "unable to create new memory cache")
			os.Exit(1)
		}
		proxy, err := dnsproxy.New(dnsListenHostPort, dnsUpstreamHostPort, cache, allowAll, noopObserve)
		if err != nil {
			logger.Error(err, "unable to create dnsproxy")
			os.Exit(1)
		}
		proxy.Start()
		defer proxy.Close()
		<-stopper
	},
}

func init() {
	rootCmd.AddCommand(dnsproxyCmd)
}
