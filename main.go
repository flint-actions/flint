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
	flag.Parse()

	data, err := os.ReadFile(*githubAppPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read github app private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	appKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse github app client key: %w", err)
	}

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

	server := server.New(ipamV4, ipamV6, appKey, *filesystem, *kernelImage, *jailerBinary, *firecrackerBinary, *bridgeInterface, *githubWebhookSecret, *githubOrganization, ipamV4.Allocate(), ipamV6.Allocate())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		log.Fatal(http.ListenAndServe(":9198", server))
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
