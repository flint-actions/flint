// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tobiaskohlbau/flint/config"
	"github.com/tobiaskohlbau/flint/network"
	"github.com/tobiaskohlbau/flint/runner"
	"github.com/tobiaskohlbau/flint/server"
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
		index := slices.IndexFunc(cfg.Runners, func(runnerConfig config.RunnerConfig) bool {
			return runnerConfig.Name == *interactive
		})
		if index == -1 {
			return fmt.Errorf("could not find runner with name %s", *interactive)
		}
		runnerConfig := cfg.Runners[index]
		net := networks[runnerConfig.Network]
		ipv4 := net.Allocate(network.IPv4)
		ipv6 := net.Allocate(network.IPv6)
		runner, err := runner.New(logger, net.Name, ipv4, ipv6, runnerConfig.Kernel, runnerConfig.Filesystem, runnerConfig.Jailer, runnerConfig.Firecracker, runnerConfig.Labels, runnerConfig.Group, net.Address(network.IPv4), net.Address(network.IPv6))
		if err != nil {
			return fmt.Errorf("failed to create runner interactive: %w", err)
		}
		runner.Interactive = true

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		go func() {
			err = runner.Start(ctx, "")
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

	server, err := server.New(logger, cfg.GitHub, cfg.Runners, networks)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	go func() {
		logger.Error("failed to run controller", "error", server.Controller(context.Background()))
		os.Exit(-1)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		err := http.ListenAndServe(cfg.Address, server)
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
