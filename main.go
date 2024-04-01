// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/tobiaskohlbau/flint/pkg/ipam"
	"github.com/tobiaskohlbau/flint/runner"
	"github.com/tobiaskohlbau/flint/server"
)

func execute(logger *slog.Logger) error {
	jailerBinary := flag.String("jailer", "", "path to jailer binary")
	firecrackerBinary := flag.String("firecracker", "", "path to firecracker binary")
	kernelImage := flag.String("kernel", "", "linux kernel image (vmlinux)")
	filesystem := flag.String("filesystem", "", "root filesystem")
	ipv4Pool := flag.String("ipv4Pool", "10.0.0.0/24", "ipv4 address pool to use for vms")
	ipv6Pool := flag.String("ipv6Pool", "fd3b:5cee:6e4c:2a55::/64", "ipv6 address pool to use for vms")
	githubAppID := flag.String("appID", "", "app id of the github app")
	githubAppPrivateKey := flag.String("privateKey", "", "private key of registered github app")
	githubWebhookSecret := flag.String("webhookSecret", "", "github webhook secret")
	githubOrganization := flag.String("organization", "", "github organization")
	bridgeInterface := flag.String("bridge", "br-flint", "bridge interface name")
	interactive := flag.Bool("interactive", false, "interactive vm without webhook")
	address := flag.String("address", ":9198", "address to listen on")
	labels := flag.String("labels", "", "labels to work on")
	email := flag.String("email", "", "E-Mail for the HTTPs certificate")
	flag.Parse()

	ipamV4, err := ipam.New(*ipv4Pool)
	if err != nil {
		return fmt.Errorf("failed to initialize ipam for ipv4: %w", err)
	}

	ipamV6, err := ipam.New(*ipv6Pool)
	if err != nil {
		return fmt.Errorf("failed to initialize ipam for ipv6: %w", err)
	}

	// reserve first ip for the host
	_ = ipamV6.Allocate()

	bridgeIPv4 := ipamV4.Allocate()
	bridgeIPv6 := ipamV6.Allocate()

	if *interactive {
		runner, err := runner.New(logger, *bridgeInterface, ipamV4.Allocate(), ipamV6.Allocate(), *kernelImage, *filesystem, *jailerBinary, *firecrackerBinary, bridgeIPv4, bridgeIPv6)
		if err != nil {
			return fmt.Errorf("failed to create runner interactive: %w", err)
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		go func() {
			err = runner.Start(ctx, "", []string{}, *interactive)
			if err != nil {
				logger.Error("failed to start interactive runner", "error", err)
				stop()
			}
		}()

		<-ctx.Done()
		logger.Info("shutting down")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := runner.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop interactive runner: %w", err)
		}

		return nil
	}

	data, err := os.ReadFile(*githubAppPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read github app private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	appKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse github app client key: %w", err)
	}

	splittedLabels := strings.Split(*labels, ",")
	server := server.New(logger, ipamV4, ipamV6, appKey, *githubAppID, *filesystem, *kernelImage, *jailerBinary, *firecrackerBinary, *bridgeInterface, *githubWebhookSecret, *githubOrganization, bridgeIPv4, bridgeIPv6, splittedLabels)

	go func() {
		logger.Error("failed to run controller", "error", server.Controller(context.Background()))
		os.Exit(-1)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		var err error

		host, port, err := net.SplitHostPort(*address)
		if err != nil {
			logger.Error("could not split host port", "error", err)
			os.Exit(-1)
		}

		if *email == "" && host != "" && port == "443" {
			logger.Error("could not activate HTTPS without email")
			os.Exit(-1)
		}

		if host != "" && port == "443" {
			certmagic.DefaultACME.Email = *email
			err = certmagic.HTTPS([]string{host}, server)
		} else {
			err = http.ListenAndServe(*address, server)
		}

		if err != nil {
			logger.Error("failed to listen", "error", err)
			os.Exit(-1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown flint: %w", err)
	}

	return nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := execute(logger); err != nil {
		logger.Error("failed to execute", "error", err)
		os.Exit(-1)
	}
}
