package fingerproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/wi1dcard/fingerproxy/pkg/certwatcher"
	"github.com/wi1dcard/fingerproxy/pkg/debug"
	fp "github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/logrotate"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
	"github.com/wi1dcard/fingerproxy/pkg/reverseproxy"
)

const logFlags = log.LstdFlags | log.Lshortfile | log.Lmsgprefix

var (
	// values are from CI build
	BuildCommit = "GIT_COMMIT_PLACEHOLDER"
	BuildTag    = "GIT_TAG_PLACEHOLDER"
)

var (
	// The loggers used by fingerproxy components
	// These will be initialized in initLoggers() function

	ProxyServerLog  *log.Logger
	HTTPServerLog   *log.Logger
	PrometheusLog   *log.Logger
	ReverseProxyLog *log.Logger
	FingerprintLog  *log.Logger
	CertWatcherLog  *log.Logger
	DefaultLog      *log.Logger

	// The Prometheus metric registry used by fingerproxy
	PrometheusRegistry = prometheus.NewRegistry()

	// The header injectors that injects fingerprint headers to forwarding requests,
	// defaults to [fingerproxy.DefaultHeaderInjectors]
	GetHeaderInjectors = DefaultHeaderInjectors
)

// initLoggers initializes all global loggers with file rotation and console output
func initLoggers() {
	var err error

	// Use provided file path or default
	logFile := *flagStdLogFile
	if logFile == "" {
		logFile = "logs/log.log"
	}

	// Create log configuration
	config := logrotate.DefaultStandardLogConfig(logFile)

	// Initialize all loggers with the same file rotation configuration
	if ProxyServerLog, err = logrotate.CreateStandardLogger(config, "[proxyserver] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize ProxyServerLog: %v", err)
	}

	if HTTPServerLog, err = logrotate.CreateStandardLogger(config, "[http] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize HTTPServerLog: %v", err)
	}

	if PrometheusLog, err = logrotate.CreateStandardLogger(config, "[metrics] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize PrometheusLog: %v", err)
	}

	if ReverseProxyLog, err = logrotate.CreateStandardLogger(config, "[reverseproxy] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize ReverseProxyLog: %v", err)
	}

	if FingerprintLog, err = logrotate.CreateStandardLogger(config, "[fingerprint] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize FingerprintLog: %v", err)
	}

	if CertWatcherLog, err = logrotate.CreateStandardLogger(config, "[certwatcher] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize CertWatcherLog: %v", err)
	}

	if DefaultLog, err = logrotate.CreateStandardLogger(config, "[fingerproxy] ", logFlags); err != nil {
		log.Fatalf("Failed to initialize DefaultLog: %v", err)
	}

	DefaultLog.Printf("Loggers initialized with file rotation: %s", logFile)
}

// DefaultHeaderInjectors is the default header injector set that injects JA3, JA4,
// and Akamai HTTP2 fingerprints. Override [fingerproxy.GetHeaderInjectors] to replace
// this to your own injectors.
func DefaultHeaderInjectors() []reverseproxy.HeaderInjector {
	h2fp := &fp.HTTP2FingerprintParam{}
	if flagMaxHTTP2PriorityFrames == nil { // if CLI flags are not initialized
		h2fp.MaxPriorityFrames = math.MaxUint
	} else {
		h2fp.MaxPriorityFrames = *flagMaxHTTP2PriorityFrames
	}

	return []reverseproxy.HeaderInjector{
		fp.NewFingerprintHeaderInjector("X-JA3-Fingerprint", "ja3", fp.JA3Fingerprint),
		fp.NewFingerprintHeaderInjector("X-JA3-RAW-Fingerprint", "ja3_text", fp.JA3RAWFingerprint),
		fp.NewFingerprintHeaderInjector("X-JA4-Fingerprint", "ja4", fp.JA4Fingerprint),
		fp.NewFingerprintHeaderInjector("X-JA4-RAW-Fingerprint", "ja4_ro", fp.JA4RAWFingerprint),
		fp.NewFingerprintHeaderInjector("X-HTTP2-Fingerprint", "akamai_text", h2fp.HTTP2Fingerprint),
	}
}

func proxyErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	ReverseProxyLog.Printf("proxy %s error (from %s): %v", req.URL.String(), req.RemoteAddr, err)

	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		rw.WriteHeader(http.StatusGatewayTimeout)
	} else {
		rw.WriteHeader(http.StatusBadGateway)
	}
}

func defaultReverseProxyHTTPHandler(forwardTo *url.URL, headerInjectors []reverseproxy.HeaderInjector) http.Handler {
	handler := reverseproxy.NewHTTPHandler(
		forwardTo,
		&httputil.ReverseProxy{
			ErrorLog:      ReverseProxyLog,
			FlushInterval: parseReverseProxyFlushInterval(),
			ErrorHandler:  proxyErrorHandler,
			// TODO: customize transport
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		headerInjectors,
	)

	handler.PreserveHost = *flagPreserveHost

	if *flagEnableKubernetesProbe {
		handler.IsProbeRequest = reverseproxy.IsKubernetesProbeRequest
	}

	// Configure JSON logger if specified
	if *flagFPLogFile != "" {
		if fileLogger, err := initFileLogger(*flagFPLogFile); err != nil {
			DefaultLog.Printf("Failed to initialize FP file logger: %v", err)
		} else {
			handler.FPFileLogger = &fileLogger
			DefaultLog.Printf("FP file logging enabled to: %s", *flagFPLogFile)
		}
	}

	return handler
}

func defaultProxyServer(ctx context.Context, handler http.Handler, tlsConfig *tls.Config) *proxyserver.Server {
	svr := proxyserver.NewServer(ctx, handler, tlsConfig)

	svr.VerboseLogs = *flagVerboseLogs
	svr.ErrorLog = ProxyServerLog
	svr.HTTPServer.ErrorLog = HTTPServerLog

	svr.MetricsRegistry = PrometheusRegistry

	svr.HTTPServer.IdleTimeout = parseHTTPIdleTimeout()
	svr.HTTPServer.ReadTimeout = parseHTTPReadTimeout()
	svr.HTTPServer.WriteTimeout = parseHTTPWriteTimeout()
	svr.TLSHandshakeTimeout = parseTLSHandshakeTimeout()

	return svr
}

func initCertWatcher() *certwatcher.CertWatcher {
	certwatcher.Logger = CertWatcherLog
	certwatcher.VerboseLogs = *flagVerboseLogs
	cw, err := certwatcher.New(*flagCertFilename, *flagKeyFilename)
	if err != nil {
		DefaultLog.Fatalf(`invalid cert filename "%s" or certkey filename "%s": %s`, *flagCertFilename, *flagKeyFilename, err)
	}
	return cw
}

func defaultTLSConfig(cw *certwatcher.CertWatcher) *tls.Config {
	return &tls.Config{
		NextProtos:     []string{"h2", "http/1.1", "http/1.0"},
		MinVersion:     tls.VersionTLS10,
		MaxVersion:     tls.VersionTLS13,
		GetCertificate: cw.GetCertificate,
	}
}

func initFingerprint() {
	fp.Logger = FingerprintLog
	fp.VerboseLogs = *flagVerboseLogs
	fp.RegisterDurationMetric(PrometheusRegistry, parseDurationMetricBuckets(), "")
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

// Run fingerproxy. To customize the fingerprinting algorithms, use "header injectors".
// See [fingerproxy.GetHeaderInjectors] for more info.
//
// Dynamic protocol support:
// The server automatically detects client capabilities and supports:
// - TLS 1.0/1.1 clients: HTTP/1.x only with JA3/JA4 fingerprints
// - TLS 1.2+ clients: HTTP/2 + HTTP/1.x with JA3/JA4/HTTP2 fingerprints
// All clients connect to the same port with automatic protocol negotiation.
func Run() {
	// CLI
	initFlags()
	parseFlags()

	// Initialize loggers with rotation after flags are parsed
	initLoggers()

	// Enable RSA key exchange for legacy client compatibility
	// This re-enables RSA key exchange algorithms that were disabled by default in Go 1.22+
	if err := os.Setenv("GODEBUG", "tlsrsakex=1"); err != nil {
		DefaultLog.Printf("Warning: failed to set GODEBUG=tlsrsakex=1: %v", err)
	} else {
		DefaultLog.Printf("Enabled RSA key exchange for legacy client support (GODEBUG=tlsrsakex=1)")
	}

	// fingerprint package
	initFingerprint()

	// tls cert watcher
	cw := initCertWatcher()

	// signal cancels context
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	// main TLS server with dynamic protocol support
	server := defaultProxyServer(
		ctx,
		defaultReverseProxyHTTPHandler(
			parseForwardURL(),
			GetHeaderInjectors(),
		),
		defaultTLSConfig(cw),
	)

	// start cert watcher
	go cw.Start(ctx)

	// metrics server
	PrometheusLog.Printf("server listening on %s", *flagMetricsListenAddr)
	go http.ListenAndServe(
		*flagMetricsListenAddr,
		promhttp.HandlerFor(PrometheusRegistry, promhttp.HandlerOpts{
			ErrorLog: PrometheusLog,
		}),
	)

	// debug server if binary build with `debug` tag
	debug.StartDebugServer()

	// start the main TLS server
	DefaultLog.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	DefaultLog.Print(err)
}
