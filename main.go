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
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/flint-actions/flint/config"
	"github.com/flint-actions/flint/network"
	"github.com/flint-actions/flint/runner"
	"github.com/flint-actions/flint/server"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v50/github"
	"golang.org/x/exp/slices"
	yaml "gopkg.in/yaml.v3"
)

func execute(logger *slog.Logger, logLevel *slog.LevelVar) error {
	interactive := flag.String("interactive", "", "interactive vm without webhook from group selected")
	logLevelFlag := flag.String("logLevel", "", "Enable debug logging")
	configPath := flag.String("config", "config.yaml", "Configuration file to load.")
	flag.Parse()

	configData, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration file: %w", err)
	}

	var cfg config.Config
	err = yaml.Unmarshal(configData, &cfg)
	if err != nil {
		return fmt.Errorf("invalid config file: %w", err)
	}

	if cfg.LogLevel == "" && *logLevelFlag != "" {
		cfg.LogLevel = *logLevelFlag
	}

	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logger.Error("invalid log level", "level", cfg.LogLevel)
		os.Exit(-1)
	}

	networks := make(map[string]*network.Network, 0)
	for _, net := range cfg.Networks {
		networks[net.Name] = network.New(net.Name, net.IPV4, net.IPV6)
	}

	if *interactive != "" {
		combined := append(cfg.Runners, cfg.StaticRunners...)
		index := slices.IndexFunc(combined, func(runnerConfig config.RunnerConfig) bool {
			fmt.Println(runnerConfig.Name)
			return runnerConfig.Name == *interactive
		})
		if index == -1 {
			return fmt.Errorf("could not find runner with name %s", *interactive)
		}
		runnerConfig := combined[index]
		net := networks[runnerConfig.Network]
		ipv4 := net.Allocate(network.IPv4)
		ipv6 := net.Allocate(network.IPv6)
		runner, err := runner.New(logger, runnerConfig.Name, net.Name, ipv4, ipv6, runnerConfig.Kernel, runnerConfig.Filesystem, runnerConfig.Jailer, runnerConfig.Firecracker, cfg.GitHub.Organization, runnerConfig.Labels, runnerConfig.Group, net.Address(network.IPv4), net.Address(network.IPv6), false)
		if err != nil {
			return fmt.Errorf("failed to create runner interactive: %w", err)
		}
		runner.Interactive = true

		go func() {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Kill)
			defer cancel()

			<-ctx.Done()

			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := runner.Stop(stopCtx); err != nil {
				logger.Error("failed to stop runner", "error", err)
			}
		}()

		err = runner.Start(context.Background(), "")
		if err != nil {
			return fmt.Errorf("failedto start interactive runner: %w", err)
		}

		if err := runner.Wait(context.Background()); err != nil {
			return fmt.Errorf("failed to wait for runner to exit: %w", err)
		}

		return nil
	}

	block, _ := pem.Decode([]byte(cfg.GitHub.PrivateKey))
	appKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse github app client key: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": cfg.GitHub.AppID,
	})

	tokenString, err := token.SignedString(appKey)
	if err != nil {
		return fmt.Errorf("failed to generate jwt token: %w", err)
	}

	client := github.NewTokenClient(ctx, tokenString)

	installation, _, err := client.Apps.FindOrganizationInstallation(ctx, cfg.GitHub.Organization)
	if err != nil {
		return fmt.Errorf("failed to find installation of app for organization: %w", err)
	}

	installationToken, _, err := client.Apps.CreateInstallationToken(ctx, installation.GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve installation token: %w", err)
	}

	authenticatedAppClient := github.NewTokenClient(ctx, installationToken.GetToken())

	registrationToken, _, err := authenticatedAppClient.Actions.CreateOrganizationRegistrationToken(ctx, cfg.GitHub.Organization)
	if err != nil {
		return fmt.Errorf("failed to retrieve orginzation self hosted runner token: %w", err)
	}

	staticRunners := []*runner.Runner{}
	for _, runnerConfig := range cfg.StaticRunners {
		net := networks[runnerConfig.Network]
		ipv4 := net.Allocate(network.IPv4)
		ipv6 := net.Allocate(network.IPv6)

		runner, err := runner.New(logger, runnerConfig.Name, net.Name, ipv4, ipv6, runnerConfig.Kernel, runnerConfig.Filesystem, runnerConfig.Jailer, runnerConfig.Firecracker, cfg.GitHub.Organization, runnerConfig.Labels, runnerConfig.Group, net.Address(network.IPv4), net.Address(network.IPv6), false)
		if err != nil {
			return fmt.Errorf("failed to create runner: %w", err)
		}

		if runnerConfig.CpuCount != 0 {
			runner.CpuCount = int64(runnerConfig.CpuCount)
		}

		if runnerConfig.MemorySize != 0 {
			runner.MemorySize = int64(runnerConfig.MemorySize)
		}

		if runnerConfig.Smt != false {
			runner.SMT = runnerConfig.Smt
		}

		if runnerConfig.DiskSize != 0 {
			runner.DiskSize = int64(runnerConfig.DiskSize)
		}

		staticRunners = append(staticRunners, runner)

		err = runner.Start(context.TODO(), registrationToken.GetToken())
		if err != nil {
			return fmt.Errorf("failed to start runner: %w", err)
		}
	}

	server, err := server.New(logger, cfg.GitHub, cfg.Runners, networks)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	go func() {
		logger.Error("failed to run controller", "error", server.Controller(context.Background()))
		os.Exit(-1)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		var err error

		host, port, err := net.SplitHostPort(cfg.Address)
		if err != nil {
			logger.Error("could not split host port", "error", err)
			os.Exit(-1)
		}
		if cfg.Email == "" && host != "" && port == "443" {
			logger.Error("could not activate HTTPS without email")
			os.Exit(-1)
		}

		if host != "" && port == "443" {
			certmagic.DefaultACME.Email = cfg.Email
			err = certmagic.HTTPS([]string{host}, server)
		} else {
			err = http.ListenAndServe(cfg.Address, server)
		}

		err = http.ListenAndServe(cfg.Address, server)
		if err != nil {
			logger.Error("failed to listen", "error", err)
			os.Exit(-1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown flint: %w", err)
	}

	for _, runner := range staticRunners {
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := runner.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop static runner: %w", err)
		}
	}

	return nil
}

func main() {
	lvl := new(slog.LevelVar)
	lvl.Set(slog.LevelInfo)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	}))

	if err := execute(logger, lvl); err != nil {
		logger.Error("failed to execute", "error", err)
		os.Exit(-1)
	}
}
