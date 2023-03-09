// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/tobiaskohlbau/flint/pkg/ipam"
	"github.com/tobiaskohlbau/flint/runner"
	"github.com/tobiaskohlbau/flint/server"
)

func execute() error {
	jailerBinary := flag.String("jailer", "", "path to jailer binary")
	firecrackerBinary := flag.String("firecracker", "", "path to firecracker binary")
	kernelImage := flag.String("kernel", "", "linux kernel image (vmlinux)")
	filesystem := flag.String("filesystem", "", "root filesystem")
	ipv4Pool := flag.String("ipv4Pool", "10.0.0.0/24", "ipv4 address pool to use for vms")
	ipv6Pool := flag.String("ipv6Pool", "fd3b:5cee:6e4c:2a55::/64", "ipv6 address pool to use for vms")
	githubAppPrivateKey := flag.String("privateKey", "", "private key of registered github app")
	githubWebhookSecret := flag.String("webhookSecret", "", "github webhook secret")
	githubOrganization := flag.String("organization", "", "github organization")
	bridgeInterface := flag.String("bridge", "br-flint", "bridge interface name")
	interactive := flag.Bool("interactive", false, "interactive vm without webhook")
	address := flag.String("address", ":9198", "address to listen on")
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
		runner, err := runner.New(1, *bridgeInterface, ipamV4.Allocate(), ipamV6.Allocate(), *kernelImage, *filesystem, *jailerBinary, *firecrackerBinary)
		if err != nil {
			return fmt.Errorf("failed to create runner interactive: %w", err)
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		go func() {
			err = runner.Start(ctx, "", bridgeIPv4, bridgeIPv6, *interactive)
			if err != nil {
				log.Println(err)
				stop()
			}
		}()

		<-ctx.Done()
		fmt.Println("shutting down")

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

	server := server.New(ipamV4, ipamV6, appKey, *filesystem, *kernelImage, *jailerBinary, *firecrackerBinary, *bridgeInterface, *githubWebhookSecret, *githubOrganization, bridgeIPv4, bridgeIPv6)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		log.Fatal(http.ListenAndServe(*address, server))
	}()

	<-ctx.Done()
	fmt.Println("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown flint: %w", err)
	}

	return nil
}

func main() {
	if err := execute(); err != nil {
		log.Fatal(err)
	}
}
