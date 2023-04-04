package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/moolen/neuwerk/pkg/controller"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	logger                  = log.DefaultLogger
	dnsListenAddr           string
	dnsUpstreamAddr         string
	verbosity               int
	bpffs                   string
	peers                   []string
	deviceName              string
	dbBindAddr              string
	dbBindPort              int
	memberListBindAddr      string
	memberListBindPort      int
	memberListAdvertiseAddr string
	memberListAdvertisePort int
)

var rootCmd = &cobra.Command{
	Use: "neuwerk",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log.WithV(verbosity)
	},
	Run: func(cmd *cobra.Command, args []string) {
		ctx := SetupSignalHandler()
		logger.Info("starting neuwerk")

		ctrl, err := controller.New(ctx, &controller.ControllerConfig{
			BPFFS:                   bpffs,
			DeviceName:              deviceName,
			DNSListenAddress:        dnsListenAddr,
			DNSUpstreamAddress:      dnsUpstreamAddr,
			Peers:                   peers,
			DBBindAddr:              dbBindAddr,
			DBBindPort:              dbBindPort,
			MemberListBindAddr:      memberListBindAddr,
			MemberListBindPort:      memberListBindPort,
			MemberListAdvertiseAddr: memberListAdvertiseAddr,
			MemberListAdvertisePort: memberListAdvertisePort,
		})
		if err != nil {
			logger.Error(err, "unable to create controller")
			os.Exit(1)
		}
		defer ctrl.Close()

		logger.Info("waiting for stop ctx")
		<-ctx.Done()
		logger.Info("shutting down")
	},
}

var onlyOneSignalHandler = make(chan struct{})
var shutdownSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

// SetupSignalHandler registers for SIGTERM and SIGINT. A context is returned
// which is canceled on one of these signals. If a second signal is caught, the program
// is terminated with exit code 1.
func SetupSignalHandler() context.Context {
	close(onlyOneSignalHandler) // panics when called twice

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return ctx
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbosity", "v", 3, "verbosity level to use")
	rootCmd.Flags().StringVar(&dnsListenAddr, "dns-listen-addr", "0.0.0.0:3333", "dnsproxy listen address")
	rootCmd.Flags().StringVar(&dnsUpstreamAddr, "dns-upstream-addr", "8.8.8.8:53", "trusted upstream DNS server address")
	rootCmd.Flags().StringVar(&bpffs, "bpffs", "/sys/fs/bpf", "bpf file system location")
	rootCmd.Flags().StringArrayVar(&peers, "peers", nil, "state cluster peers")
	rootCmd.Flags().StringVar(&deviceName, "net-device", "wlp61s0", "name of the network device to attach the tc filter to")
	rootCmd.Flags().StringVar(&dbBindAddr, "db-bind-addr", "0.0.0.0", "db address to listen on")
	rootCmd.Flags().IntVar(&dbBindPort, "db-bind-port", 3320, "db port to listen on")
	rootCmd.Flags().StringVar(&memberListBindAddr, "memberlist-bind-addr", "0.0.0.0", "memberlist address to listen on")
	rootCmd.Flags().IntVar(&memberListBindPort, "memberlist-bind-port", 3322, "memberlist port to listen on")
	rootCmd.Flags().StringVar(&memberListAdvertiseAddr, "memberlist-advertise-addr", "0.0.0.0", "memberlist address to advertise")
	rootCmd.Flags().IntVar(&memberListAdvertisePort, "memberlist-advertise-port", 3322, "memberlist port to advertise")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
