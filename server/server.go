// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/flint-actions/flint/config"
	"github.com/flint-actions/flint/network"
	"github.com/flint-actions/flint/runner"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v50/github"
	"golang.org/x/exp/slices"
)

type Server struct {
	logger *slog.Logger

	key           *rsa.PrivateKey
	id            string
	organization  string
	webhookSecret string

	// guards the following fields
	m             sync.Mutex
	runner        map[string]*runner.Runner
	processedJobs map[int64]any

	runnerConfigs []config.RunnerConfig
	networks      map[string]*network.Network
}

func New(logger *slog.Logger, githubConfig config.GitHubConfig, runnerConfigs []config.RunnerConfig, networks map[string]*network.Network) (*Server, error) {
	block, _ := pem.Decode([]byte(githubConfig.PrivateKey))
	appKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse github app client key: %w", err)
	}

	for _, config := range runnerConfigs {
		slices.Sort(config.Labels)
	}

	return &Server{
		logger:        logger,
		key:           appKey,
		id:            githubConfig.AppID,
		runner:        make(map[string]*runner.Runner),
		processedJobs: make(map[int64]any),
		organization:  githubConfig.Organization,
		webhookSecret: githubConfig.WebhookSecret,
		runnerConfigs: runnerConfigs,
		networks:      networks,
	}, nil
}

func (s *Server) runnerByName(name string) (*runner.Runner, error) {
	s.m.Lock()
	defer s.m.Unlock()

	runner, ok := s.runner[name]
	if !ok {
		return nil, fmt.Errorf("runner with name not found: %s", name)
	}
	return runner, nil
}

func (s *Server) hasProcessedJob(id int64) bool {
	s.m.Lock()
	defer s.m.Unlock()
	_, ok := s.processedJobs[id]
	return ok
}

func (s *Server) removeRunner(runner *runner.Runner) {
	s.m.Lock()
	defer s.m.Unlock()
	delete(s.runner, runner.ID())
}

func (s *Server) addRunner(runner *runner.Runner) {
	s.m.Lock()
	defer s.m.Unlock()
	s.runner[runner.ID()] = runner
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.m.Lock()
	defer s.m.Unlock()
	for _, r := range s.runner {
		if err := r.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop runner %s", r.ID())
		}
	}
	return nil
}

func (s *Server) handleQueuedEvent(ctx context.Context, job *github.WorkflowJob) error {
	if s.hasProcessedJob(job.GetID()) {
		s.logger.Info("queued event for job already handled", "job_id", job.GetID())
		return nil
	}

	cfg, ok := shouldHandleEvent(job, s.runnerConfigs)
	if !ok {
		s.logger.Debug("not resposible for job", "job_id", job.GetID())
		return nil
	}

	s.logger.Info("received queued event", "job_id", job.GetID())

	net := s.networks[cfg.Network]
	ipv4 := net.Allocate(network.IPv4)
	ipv6 := net.Allocate(network.IPv6)

	runner, err := runner.New(s.logger, net.Name, ipv4, ipv6, cfg.Kernel, cfg.Filesystem, cfg.Jailer, cfg.Firecracker, s.organization, cfg.Labels, cfg.Group, net.Address(network.IPv4), net.Address(network.IPv6))
	if err != nil {
		return fmt.Errorf("failed to create runner: %w", err)
	}

	if cfg.CpuCount != 0 {
		runner.CpuCount = int64(cfg.CpuCount)
	}

	if cfg.MemorySize != 0 {
		runner.MemorySize = int64(cfg.MemorySize)
	}

	if cfg.Smt != false {
		runner.SMT = cfg.Smt
	}

	if cfg.DiskSize != 0 {
		runner.DiskSize = int64(cfg.DiskSize)
	}

	log.Printf("spawning selfhosted runner: %s", runner.ID())

	installationClient, err := s.newInstallationGitHubClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create installation client: %w", err)
	}

	registrationToken, _, err := installationClient.Actions.CreateOrganizationRegistrationToken(ctx, s.organization)
	if err != nil {
		return fmt.Errorf("failed to retrieve orginzation self hosted runner token: %w", err)
	}

	vmmContext, _ := context.WithTimeout(context.Background(), 120*time.Minute)
	err = runner.Start(vmmContext, registrationToken.GetToken())
	if err != nil {
		return fmt.Errorf("failed to start runner: %w", err)
	}

	log.Printf("launched runner %s", runner.ID())

	s.addRunner(runner)

	return nil
}

func (s *Server) handleCompletedEvent(ctx context.Context, job *github.WorkflowJob) error {
	cfg, ok := shouldHandleEvent(job, s.runnerConfigs)
	if !ok {
		return nil
	}

	s.logger.Info("received completed event", "job_id", job.GetID())

	runnerName := job.GetRunnerName()
	runner, err := s.runnerByName(runnerName)
	if err != nil {
		return fmt.Errorf("failed to get runner by name: %w", err)
	}

	if err := runner.Stop(ctx); err != nil {
		log.Println(err)
	}

	net := s.networks[cfg.Network]
	net.Release(runner.IPv4())
	net.Release(runner.IPv6())

	s.removeRunner(runner)
	delete(s.processedJobs, job.GetID())

	return nil
}

func (s *Server) newInstallationGitHubClient(ctx context.Context) (*github.Client, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": s.id,
	})

	tokenString, err := token.SignedString(s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt token: %w", err)
	}

	client := github.NewTokenClient(ctx, tokenString)

	installation, _, err := client.Apps.FindOrganizationInstallation(ctx, s.organization)
	if err != nil {
		return nil, fmt.Errorf("failed to find installation of app for organization: %w", err)
	}

	installationToken, _, err := client.Apps.CreateInstallationToken(ctx, installation.GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve installation token: %w", err)
	}

	return github.NewTokenClient(ctx, installationToken.GetToken()), nil
}

func unifyLabels(labels []string) []string {
	out := make([]string, len(labels))
	for i, label := range labels {
		out[i] = strings.ToLower(label)
	}
	slices.Sort(out)
	return out
}

func shouldHandleEvent(job *github.WorkflowJob, runners []config.RunnerConfig) (config.RunnerConfig, bool) {
	if !slices.Contains(job.Labels, "self-hosted") {
		return config.RunnerConfig{}, false
	}

	jobLabels := unifyLabels(job.Labels)
	for _, runner := range runners {
		runnerLabels := unifyLabels(runner.Labels)
		if slices.Equal(runnerLabels, jobLabels) {
			return runner, true
		}
	}

	return config.RunnerConfig{}, false
}

func (s *Server) Controller(ctx context.Context) error {
	installationClient, err := s.newInstallationGitHubClient(ctx)
	if err != nil {
		return err
	}
	for ; ; time.Sleep(5 * time.Minute) {
		page := 1
		for {
			repositories, resp, err := installationClient.Apps.ListRepos(ctx, &github.ListOptions{
				Page:    page,
				PerPage: 100,
			})
			if err != nil {
				log.Printf("failed to list organization repositories: %v", err)

				installationClient, err = s.newInstallationGitHubClient(ctx)
				if err != nil {
					return fmt.Errorf("failed to renew installation client: %w", err)
				}

				continue
			}
			for _, repo := range repositories.Repositories {
				if *repo.Archived {
					continue
				}

				owner := repo.GetOwner().GetLogin()
				name := repo.GetName()

				queuedWorkflows, _, err := installationClient.Actions.ListRepositoryWorkflowRuns(ctx, owner, name, &github.ListWorkflowRunsOptions{
					Status: "queued",
				})

				if err != nil {
					log.Printf("failed to list queued workflows for repository %s: %v", repo.GetName(), err)
					continue
				}

				for _, workflow := range queuedWorkflows.WorkflowRuns {
					jobs, _, err := installationClient.Actions.ListWorkflowJobs(ctx, owner, name, workflow.GetID(), &github.ListWorkflowJobsOptions{})
					if err != nil {
						log.Printf("failed to retrieve jobs for worfklow %s on repository %s: %v", workflow.GetName(), workflow.GetRepository().GetName(), err)
						continue
					}

					for _, job := range jobs.Jobs {
						if job.GetStatus() != "queued" {
							continue
						}

						if job.GetCreatedAt().Add(1 * time.Minute).After(time.Now()) {
							// webhook maybe pending
							continue
						}

						if err := s.handleQueuedEvent(ctx, job); err != nil {
							log.Println(err)
						}
					}
				}
			}

			if resp.NextPage == 0 {
				break
			}
			page = resp.NextPage
		}
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/webhook") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	payload, err := github.ValidatePayload(r, []byte(s.webhookSecret))
	if err != nil {
		s.logger.Error("failed to validate payload", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return

	}
	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		s.logger.Error("failed to parse webhook", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.logger.Debug("received webhook event", "event", event)

	switch event := event.(type) {
	case *github.WorkflowJobEvent:
		if event.GetAction() == "queued" {
			if err := s.handleQueuedEvent(r.Context(), event.GetWorkflowJob()); err != nil {
				s.logger.Error("failed to handle queued event", "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}
		if event.GetAction() == "completed" {
			if err := s.handleCompletedEvent(r.Context(), event.GetWorkflowJob()); err != nil {
				s.logger.Error("failed to handle completed event", "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}
	}
}
