package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/moolen/neuwerk/pkg/controller"
	integr "github.com/moolen/neuwerk/pkg/integration"
	"github.com/moolen/neuwerk/pkg/log"
	"github.com/moolen/neuwerk/pkg/ruleset"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	logger              = log.DefaultLogger
	integration         string
	clusterName         string
	configFile          string
	dnsListenHostPort   string
	dnsUpstreamHostPort string
	verbosity           int
	bpffs               string
	peers               []string
	deviceName          string
	dbBindPort          int
	mgmtPort            int
	mgmtAddress         string
)

var rootCmd = &cobra.Command{
	Use: "neuwerk",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log.WithV(verbosity)
	},
	Run: func(cmd *cobra.Command, args []string) {
		ctx := SetupSignalHandler()
		logger.Info("starting neuwerk")

		fileWatcher, err := ruleset.NewFileWatcher(configFile)
		if err != nil {
			logger.Error(err, "unable to create file watcher", "file", configFile)
			os.Exit(1)
		}

		ctrlConfig := &controller.ControllerConfig{
			ClusterName:         clusterName,
			Integration:         integration,
			BPFFS:               bpffs,
			EgressDeviceName:    deviceName,
			DNSListenHostPort:   dnsListenHostPort,
			DNSUpstreamHostPort: dnsUpstreamHostPort,
			Peers:               peers,
			DBBindPort:          dbBindPort,
			MgmtPort:            mgmtPort,
			ManagementAddress:   mgmtAddress,
			RuleProvider:        fileWatcher,
		}

		// integration may change controller config
		err = integr.Apply(ctx, integration, ctrlConfig)
		if err != nil {
			logger.Error(err, "unable to apply aws integration")
			os.Exit(1)
		}

		ctrl, err := controller.New(ctx, ctrlConfig)
		if err != nil {
			logger.Error(err, "unable to create controller")
			os.Exit(1)
		}
		defer ctrl.Close()

		http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}))
		go func() {
			err := http.ListenAndServe(":3000", nil)
			if err != nil {
				logger.Error(err, "unable to listen http")
			}
		}()

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
	rootCmd.Flags().StringVar(&clusterName, "cluster-name", "default", "name of the cluster")
	rootCmd.PersistentFlags().IntVarP(&verbosity, "verbosity", "v", 1, "verbosity level to use")
	rootCmd.Flags().StringVar(&integration, "integration", "aws", "integration type to use")
	rootCmd.Flags().StringVar(&configFile, "config", "config.yaml", "config file to use")
	rootCmd.Flags().StringVar(&dnsListenHostPort, "dns-listen-host-port", "0.0.0.0:53", "dnsproxy listen address")
	rootCmd.Flags().StringVar(&dnsUpstreamHostPort, "dns-upstream-host-port", "8.8.8.8:53", "trusted upstream DNS server address")
	rootCmd.Flags().StringVar(&bpffs, "bpffs", "/sys/fs/bpf", "bpf file system location")
	rootCmd.Flags().StringArrayVar(&peers, "peers", nil, "state cluster peers")
	rootCmd.Flags().StringVar(&deviceName, "net-device", "wlan0", "name of the network device to attach the tc filter to")
	rootCmd.Flags().IntVar(&dbBindPort, "db-bind-port", 3320, "db port to listen on")
	rootCmd.Flags().IntVar(&mgmtPort, "mgmt-bind-port", 3322, "mgmt port to listen on")
	rootCmd.Flags().StringVar(&mgmtAddress, "mgmt-address", "127.0.0.1", "mgmt port to listen on")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
