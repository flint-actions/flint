// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-github/v50/github"
	"github.com/tobiaskohlbau/flint/pkg/ipam"
	"github.com/tobiaskohlbau/flint/runner"
)

type Server struct {
	ipamV4 *ipam.IPAM
	ipamV6 *ipam.IPAM
	key    *rsa.PrivateKey
	id     string

	// guards the following two fields
	m         sync.Mutex
	githubMap map[int64]string
	runner    map[string]*runner.Runner

	filesystem        string
	kernelImage       string
	jailerBinary      string
	firecrackerBinary string
	bridgeInterface   string
	bridgeIPv4        netip.Addr
	bridgeIPv6        netip.Addr
	organization      string
	webhookSecret     string
}

func New(ipamV4 *ipam.IPAM, ipamV6 *ipam.IPAM, key *rsa.PrivateKey, id string, filesystem, kernelImage, jailerBinary, firecrackerBinary, bridgeInterface, webhookSecret, organization string, bridgeIPv4 netip.Addr, bridgeIPv6 netip.Addr) *Server {
	return &Server{
		ipamV4:            ipamV4,
		ipamV6:            ipamV6,
		key:               key,
		id:                id,
		filesystem:        filesystem,
		kernelImage:       kernelImage,
		jailerBinary:      jailerBinary,
		firecrackerBinary: firecrackerBinary,
		bridgeInterface:   bridgeInterface,
		webhookSecret:     webhookSecret,
		bridgeIPv4:        bridgeIPv4,
		bridgeIPv6:        bridgeIPv6,
		organization:      organization,
		githubMap:         make(map[int64]string),
		runner:            make(map[string]*runner.Runner),
	}
}

func (s *Server) runnerByGitHubID(id int64) (*runner.Runner, error) {
	s.m.Lock()
	defer s.m.Unlock()
	runnerID, ok := s.githubMap[id]
	if !ok {
		return nil, fmt.Errorf("runner with id not found: %d", id)
	}

	runner, ok := s.runner[runnerID]
	if !ok {
		return nil, fmt.Errorf("runner with internal id not found: %d", id)
	}
	return runner, nil
}

func (s *Server) hasRunnerForGithubID(id int64) bool {
	s.m.Lock()
	defer s.m.Unlock()
	_, ok := s.githubMap[id]
	return ok
}

func (s *Server) removeRunner(runner *runner.Runner) {
	s.m.Lock()
	defer s.m.Unlock()
	s.ipamV4.Release(runner.IPv4())
	s.ipamV6.Release(runner.IPv6())
	delete(s.githubMap, runner.GitHubID())
	delete(s.runner, runner.ID())
}

func (s *Server) addRunner(runner *runner.Runner) {
	s.m.Lock()
	defer s.m.Unlock()
	s.githubMap[runner.GitHubID()] = runner.ID()
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

func (s *Server) handleQueuedEvent(ctx context.Context, id int64) error {
	if s.hasRunnerForGithubID(id) {
		log.Printf("ignoring event, runner for %d already exists", id)
		return nil
	}

	runner, err := runner.New(id, s.bridgeInterface, s.ipamV4.Allocate(), s.ipamV6.Allocate(), s.kernelImage, s.filesystem, s.jailerBinary, s.firecrackerBinary)
	if err != nil {
		return fmt.Errorf("failed to create runner: %w", err)
	}

	log.Printf("spawning selfhosted runner: %s", runner.ID())

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": id,
	})

	tokenString, err := token.SignedString(s.key)
	if err != nil {
		return fmt.Errorf("failed to generate jwt token: %w", err)
	}

	client := github.NewTokenClient(ctx, tokenString)

	installation, _, err := client.Apps.FindOrganizationInstallation(ctx, s.organization)
	if err != nil {
		return fmt.Errorf("failed to find installation of app for organization: %w", err)
	}

	installationToken, _, err := client.Apps.CreateInstallationToken(ctx, installation.GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve installation token: %w", err)
	}

	installationClient := github.NewTokenClient(ctx, installationToken.GetToken())
	registrationToken, _, err := installationClient.Actions.CreateOrganizationRegistrationToken(ctx, s.organization)
	if err != nil {
		return fmt.Errorf("failed to retrieve orginzation self hosted runner token: %w", err)
	}

	vmmContext, _ := context.WithTimeout(context.Background(), 120*time.Minute)
	err = runner.Start(vmmContext, registrationToken.GetToken(), s.bridgeIPv4, s.bridgeIPv6, false)
	if err != nil {
		return fmt.Errorf("failed to start runner: %w", err)
	}

	s.addRunner(runner)

	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/webhook") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	payload, err := github.ValidatePayload(r, []byte(s.webhookSecret))
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return

	}
	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		log.Println(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	switch event := event.(type) {
	case *github.WorkflowJobEvent:
		needsSelfhosted := false
		for _, label := range event.GetWorkflowJob().Labels {
			if label == "self-hosted" {
				needsSelfhosted = true
				break
			}
		}
		if event.GetAction() == "queued" && needsSelfhosted {
			log.Printf("Received queued event with id: %d", event.GetWorkflowJob().GetRunID())
			if err := s.handleQueuedEvent(r.Context(), event.GetWorkflowJob().GetRunID()); err != nil {
				log.Println(err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}
		if event.GetAction() == "completed" && needsSelfhosted {
			log.Printf("received shutdown event")

			runID := event.GetWorkflowJob().GetRunID()
			runner, err := s.runnerByGitHubID(runID)
			if err != nil {
				log.Println(err)
				return
			}
			if err := runner.Stop(r.Context()); err != nil {
				log.Println(err)
			}
			s.removeRunner(runner)
		}
	default:
		ev := event.(github.Event)
		log.Printf("ignoring %s event", ev.GetType())
	}
}
