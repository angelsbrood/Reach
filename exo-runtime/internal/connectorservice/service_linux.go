//go:build linux

// Package connectorservice gives the existing connector a Linux service lifecycle.
package connectorservice

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/gateway"
	"reach.dev/exo-runtime/internal/mtls"
)

// StartupError identifies failures which require an operator correction, not a restart.
// Stage is safe to log; the underlying error may contain operator-supplied data.
type StartupError struct {
	Stage string
	Err   error
}

func (e *StartupError) Error() string { return "connector startup refused: " + e.Stage }
func (e *StartupError) Unwrap() error { return e.Err }

// Run serves the unchanged loopback proxy. A nil notifier is explicit foreground
// operation; notification otherwise occurs only after Serve enters its accept loop.
func Run(ctx context.Context, path string, notify func(string) error) error {
	value, err := config.LoadConnector(path)
	if err != nil {
		return &StartupError{"configuration", err}
	}
	if err = config.ValidateTLSFileModes(value.TLS, false); err != nil {
		return &StartupError{"credentials", err}
	}
	tlsConfig, err := mtls.Client(value.TLS, value.ServerName)
	if err != nil {
		return &StartupError{"credentials", err}
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := net.Listen("tcp4", value.ListenAddress)
	if err != nil {
		return &StartupError{"listener", err}
	}
	transport := gateway.TLSTransport(tlsConfig)
	defer transport.CloseIdleConnections()
	server := &http.Server{
		Handler:           gateway.Handler(transport, &url.URL{Scheme: "https", Host: value.GatewayAddress}, "connector"),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 * 1024,
	}
	return serve(ctx, listener, server, notify)
}

type servingListener struct {
	net.Listener
	ready chan struct{}
	once  sync.Once
}

func (l *servingListener) Accept() (net.Conn, error) {
	l.once.Do(func() { close(l.ready) })
	return l.Listener.Accept()
}

func serve(ctx context.Context, listener net.Listener, server *http.Server, notify func(string) error) error {
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- server.Serve(&servingListener{Listener: listener, ready: ready}) }()
	// Every return closes the listener/connections and joins the serving goroutine.
	joined := false
	defer func() {
		_ = server.Close()
		_ = listener.Close()
		if !joined {
			<-done
		}
	}()
	select {
	case err := <-done:
		joined = true
		return &StartupError{"listener", err}
	case <-ctx.Done():
		return nil
	case <-ready:
	}
	if ctx.Err() != nil {
		return nil
	}
	select {
	case err := <-done:
		joined = true
		return &StartupError{"listener", err}
	default:
	}
	if notify != nil {
		if err := notify("READY=1\nSTATUS=Local connector listening; upstream readiness is separate"); err != nil {
			return &StartupError{"notification", err}
		}
	}
	select {
	case err := <-done:
		joined = true
		return err
	case <-ctx.Done():
		if notify != nil {
			_ = notify("STOPPING=1")
		}
		deadline, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return server.Shutdown(deadline)
	}
}
