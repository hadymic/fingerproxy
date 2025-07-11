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
	"path/filepath"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/wi1dcard/fingerproxy/pkg/debug"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
)

var (
	flagListenAddr, flagCertFilename, flagKeyFilename, flagFPLogFile *string

	flagBenchmarkControlGroup, flagVerbose, flagQuiet *bool

	tlsConf *tls.Config

	// 全局文件日志记录器
	fpFileLogger *zerolog.Logger

	ctx, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
)

func main() {
	parseFlags()

	setupTLSConfig()

	initFileLog()

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
	flagVerbose = flag.Bool("verbose", false, "Print fingerprint detail in logs, conflict with -quiet")
	flagQuiet = flag.Bool("quiet", false, "Do not print fingerprints in logs, conflict with -verbose")
	flag.Parse()

	if *flagVerbose && *flagQuiet {
		log.Fatal("-verbose and -quiet cannot be specified at the same time")
	}
}

func setupTLSConfig() {
	tlsConf = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
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
			log.Printf("Failed to initialize FP file logger: %v", err)
		} else {
			fpFileLogger = &fileLogger
			log.Printf("FP file logging enabled to: %s", *flagFPLogFile)
		}
	}
}

func initFileLogger(filePath string) (zerolog.Logger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return zerolog.Logger{}, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Open file for writing (create if not exists, append mode)
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return zerolog.Logger{}, fmt.Errorf("failed to open log file %s: %w", filePath, err)
	}

	// Create zerolog logger with JSON output (without default timestamp since we add custom one)
	logger := zerolog.New(file)
	return logger, nil
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
	log.Printf("server (benchmark control group) listening on %s", *flagListenAddr)
	err := server.ListenAndServeTLS("", "")
	log.Fatal(err)
}

func run() {
	// create proxyserver
	server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)

	// start debug server if build tag `debug` is specified
	debug.StartDebugServer()

	// listen and serve
	log.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	log.Fatal(err)
}
