package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/wi1dcard/fingerproxy/pkg/debug"
	"github.com/wi1dcard/fingerproxy/pkg/logrotate"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
)

var (
	flagListenAddr, flagCertFilename, flagKeyFilename, flagFPLogFile, flagStdLogFile *string

	flagBenchmarkControlGroup, flagVerbose, flagQuiet *bool

	tlsConf *tls.Config

	// 全局文件日志记录器
	fpFileLogger *zerolog.Logger

	// 标准库日志记录器
	stdLogger *log.Logger

	ctx, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
)

func main() {
	parseFlags()

	// 初始化标准库日志
	initStdLog()

	initFileLog()

	// Enable RSA key exchange for legacy client compatibility
	// This re-enables RSA key exchange algorithms that were disabled by default in Go 1.22+
	if err := os.Setenv("GODEBUG", "tlsrsakex=1"); err != nil {
		stdLogger.Printf("Warning: failed to set GODEBUG=tlsrsakex=1: %v", err)
	} else {
		stdLogger.Printf("Enabled RSA key exchange for legacy client support (GODEBUG=tlsrsakex=1)")
	}

	setupTLSConfig()

	if *flagBenchmarkControlGroup {
		runAsControlGroup()
	} else {
		run()
	}
}

func parseFlags() {
	flagListenAddr = flag.String(
		"listen-addr",
		"localhost:8443",
		"Listening address",
	)
	flagCertFilename = flag.String(
		"cert-filename",
		"tls.crt",
		"TLS certificate filename",
	)
	flagKeyFilename = flag.String(
		"certkey-filename",
		"tls.key",
		"TLS certificate key file name",
	)
	flagBenchmarkControlGroup = flag.Bool(
		"benchmark-control-group",
		false,
		"Start a golang default TLS server as the control group for benchmarking",
	)
	flagFPLogFile = flag.String(
		"fp-log-file",
		"/data/logs/fp.log",
		"Fingerprint log file",
	)
	flagStdLogFile = flag.String(
		"std-log-file",
		"logs/log.log",
		"standard library log file path, default logs/log.log, equivalent to $STD_LOG_FILE",
	)
	flagVerbose = flag.Bool("verbose", false, "Print fingerprint detail in logs, conflict with -quiet")
	flagQuiet = flag.Bool("quiet", false, "Do not print fingerprints in logs, conflict with -verbose")
	flag.Parse()

	if *flagVerbose && *flagQuiet {
		log.Fatal("-verbose and -quiet cannot be specified at the same time")
	}
}

func setupTLSConfig() {
	tlsConf = &tls.Config{
		NextProtos: []string{"h2", "http/1.1", "http/1.0"},
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
	}

	if tlsCert, err := tls.LoadX509KeyPair(*flagCertFilename, *flagKeyFilename); err != nil {
		log.Fatal(err)
	} else {
		tlsConf.Certificates = []tls.Certificate{tlsCert}
	}
}

func initFileLog() {
	if *flagFPLogFile != "" {
		if fileLogger, err := initFileLogger(*flagFPLogFile); err != nil {
			stdLogger.Printf("Failed to initialize FP file logger: %v", err)
		} else {
			fpFileLogger = &fileLogger
			stdLogger.Printf("FP file logging enabled to: %s", *flagFPLogFile)
		}
	}
}

func initFileLogger(filePath string) (zerolog.Logger, error) {
	// Create log configuration with rotation
	config := logrotate.DefaultZerologConfig(filePath)

	// Create zerolog logger with rotation
	logger, err := logrotate.CreateZerologLogger(config)
	if err != nil {
		return zerolog.Logger{}, fmt.Errorf("failed to create rotating logger for %s: %w", filePath, err)
	}

	return logger, nil
}

func initStdLog() {
	if *flagStdLogFile != "" {
		// 创建带滚动功能的标准库日志配置
		config := logrotate.DefaultStandardLogConfig(*flagStdLogFile)

		// 创建支持双输出和滚动的logger
		logger, err := logrotate.CreateStandardLogger(config, "[echo-server] ", log.LstdFlags)
		if err != nil {
			log.Fatalf("Failed to create rotating logger for %s: %v", *flagStdLogFile, err)
		}

		stdLogger = logger
		stdLogger.Printf("Standard library logging with rotation enabled to: %s", *flagStdLogFile)
	} else {
		stdLogger = log.Default()
		log.Printf("Standard library logging enabled to default (stdout)")
	}
}

func runAsControlGroup() {
	// create golang default https server
	server := &http.Server{
		Addr:      *flagListenAddr,
		Handler:   http.HandlerFunc(echoServer),
		TLSConfig: tlsConf,
	}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	// listen and serve
	stdLogger.Printf("server (benchmark control group) listening on %s", *flagListenAddr)
	err := server.ListenAndServeTLS("", "")
	log.Fatal(err)
}

func run() {
	// create proxyserver
	server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)

	// start debug server if build tag `debug` is specified
	debug.StartDebugServer()

	// listen and serve
	stdLogger.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	log.Fatal(err)
}
