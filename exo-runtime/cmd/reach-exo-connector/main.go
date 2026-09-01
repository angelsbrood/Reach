package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/gateway"
	"reach.dev/exo-runtime/internal/mtls"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: reach-exo-connector /absolute/path/connector.json")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string) error {
	value, err := config.LoadConnector(path)
	if err != nil {
		return err
	}
	if err := config.ValidateTLSFileModes(value.TLS, false); err != nil {
		return err
	}
	tlsConfig, err := mtls.Client(value.TLS, value.ServerName)
	if err != nil {
		return err
	}
	target := &url.URL{Scheme: "https", Host: value.GatewayAddress}
	handler := gateway.Handler(gateway.TLSTransport(tlsConfig), target, "connector")
	listener, err := net.Listen("tcp4", value.ListenAddress)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
