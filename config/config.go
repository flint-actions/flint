// Copyright 2023 The Flint Authors.
// SPDX-License-Identifier: Apache-2.0

package config

type Config struct {
	LogLevel string          `yaml:"logLevel"`
	Runners  []RunnerConfig  `yaml:"runners"`
	Address  string          `yaml:"address"`
	Email    string          `yaml:"email"`
	GitHub   GitHubConfig    `yaml:"github"`
	Networks []NetworkConfig `yaml:"networks"`
}

type RunnerConfig struct {
	Name        string   `yaml:"name"`
	Group       string   `yaml:"group"`
	Labels      []string `yaml:"labels"`
	Kernel      string   `yaml:"kernel"`
	Filesystem  string   `yaml:"filesystem"`
	Network     string   `yaml:"network"`
	Jailer      string   `yaml:"jailer"`
	Firecracker string   `yaml:"firecracker"`
	CpuCount    int      `yaml:"cpuCount"`
	MemorySize  int      `yaml:"memorySize"`
	Smt         bool     `yaml:"smt"`
	DiskSize    int      `yaml:"diskSize"`
}

type NetworkConfig struct {
	Name string `yaml:"name"`
	IPV4 string `yaml:"v4"`
	IPV6 string `yaml:"v6"`
}

type GitHubConfig struct {
	AppID         string `yaml:"appID"`
	PrivateKey    string `yaml:"privateKey"`
	Organization  string `yaml:"organization"`
	WebhookSecret string `yaml:"webhookSecret"`
}
