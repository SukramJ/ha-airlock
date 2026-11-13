// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Command ha-airlock is the MCP server and the composition root of the
// module. So far it reports its version, measures as "ha-airlock probe" from
// inside the App container which ways to Home Assistant Core are open, and
// checks an audit log as "ha-airlock audit verify FILE", gives itself a Home
// Assistant user as "ha-airlock provision", and as "ha-airlock serve" is the
// server: the consent page for the Supervisor, and the authorization server
// and MCP endpoint behind the owner's reverse proxy.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/build"
	"github.com/SukramJ/ha-airlock/internal/oauth"
	"github.com/SukramJ/ha-airlock/internal/probe"
	"github.com/SukramJ/ha-airlock/internal/provision"
	"github.com/SukramJ/ha-airlock/internal/supervisor"
)

// environment is what the process takes from its surroundings. The names
// under which an App reaches the Supervisor and Core are the ones the
// Supervisor writes into the App's hosts file.
type environment struct {
	supervisorURL   string
	supervisorToken string
	coreHost        string
	// dataDir is the directory the Supervisor keeps for the App across
	// restarts and updates.
	dataDir string
	// ingressAddr is where the Supervisor reaches the consent page,
	// publicAddr where the owner's reverse proxy reaches everything else.
	ingressAddr string
	publicAddr  string
	// supervisorPeers returns the addresses from which the Supervisor
	// connects to the ingress listener.
	supervisorPeers func(ctx context.Context) ([]netip.Addr, error)
	// clientMetadata fetches the metadata document of an OAuth client from
	// the internet.
	clientMetadata oauth.MetadataFetcher
	// onListening, if set, is told the bound addresses once the listeners
	// are up.
	onListening func(map[string]net.Addr)
	// now is the clock by which approvals expire; sweepEvery is how often
	// the server looks for expired ones.
	now        func() time.Time
	sweepEvery time.Duration
}

const (
	exitOK = iota
	exitFailed
	exitUsage
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	env := environment{
		supervisorURL:   "http://supervisor",
		supervisorToken: os.Getenv("SUPERVISOR_TOKEN"),
		coreHost:        "homeassistant",
		dataDir:         "/data",
		ingressAddr:     ":8099",
		publicAddr:      ":8443",
		supervisorPeers: func(ctx context.Context) ([]netip.Addr, error) {
			return lookupSupervisor(ctx, "supervisor")
		},
		clientMetadata: oauth.NewFetcher(),
		now:            time.Now,
		sweepEvery:     sweepEvery,
	}
	code := run(ctx, os.Args[1:], env, os.Stdout)
	stop()
	os.Exit(code)
}

// run is the whole program behind main, so that a test drives the same
// wiring the binary uses.
func run(ctx context.Context, args []string, env environment, stdout io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintf(stdout, "ha-airlock %s\n", build.Version); err != nil {
			return exitFailed
		}
		return exitOK
	}

	if args[0] == "tools" {
		// Plain output, not log lines: this is the published tools page.
		if err := writeToolsDoc(stdout); err != nil {
			return exitFailed
		}
		return exitOK
	}

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	switch args[0] {
	case "probe":
		return runProbe(ctx, env, logger)
	case "serve":
		return runServe(ctx, env, logger)
	case "provision":
		return runProvision(ctx, env, logger)
	case "audit":
		return runAudit(ctx, args[1:], stdout, logger)
	default:
		logger.ErrorContext(ctx, "unknown command", slog.String("command", args[0]))
		return exitUsage
	}
}

func runProbe(ctx context.Context, env environment, logger *slog.Logger) int {
	if env.supervisorToken == "" {
		logger.ErrorContext(ctx, "SUPERVISOR_TOKEN is not set; the probe runs inside the App container")
		return exitUsage
	}
	logger.InfoContext(ctx, "probe starts", slog.String("version", build.Version))
	report := probe.New(probe.Config{
		SupervisorURL:   env.supervisorURL,
		SupervisorToken: env.supervisorToken,
		CoreHost:        env.coreHost,
		Timeout:         10 * time.Second,
		Logger:          logger,
	}).Run(ctx)
	if !report.OK() {
		logger.WarnContext(ctx, "probe finished: not every way is open")
		return exitFailed
	}
	logger.InfoContext(ctx, "probe finished: every way is open")
	return exitOK
}

// runAudit handles "audit verify FILE": it checks the hash chain of an audit
// log and prints how many records it holds and the hash of the last one.
func runAudit(ctx context.Context, args []string, stdout io.Writer, logger *slog.Logger) int {
	if len(args) != 2 || args[0] != "verify" {
		logger.ErrorContext(ctx, "usage: ha-airlock audit verify FILE")
		return exitUsage
	}
	summary, err := audit.VerifyFile(args[1])
	if err != nil {
		logger.ErrorContext(ctx, "audit log does not verify", slog.Any("error", err))
		return exitFailed
	}
	if _, err := fmt.Fprintf(stdout, "ok: %d records, head %s\n", summary.Records, summary.Head); err != nil {
		return exitFailed
	}
	return exitOK
}

// runProvision handles "provision": it makes sure ha-airlock has its own
// Home Assistant user and a credential for it, and records a creation in
// the audit log.
func runProvision(ctx context.Context, env environment, logger *slog.Logger) int {
	if env.supervisorToken == "" {
		logger.ErrorContext(ctx, "SUPERVISOR_TOKEN is not set; provisioning runs inside the App container")
		return exitUsage
	}
	coreURL, err := supervisor.CoreURL(ctx, env.supervisorURL, env.supervisorToken, env.coreHost)
	if err != nil {
		logger.ErrorContext(ctx, "cannot learn where Core listens", slog.Any("error", err))
		return exitFailed
	}
	auditLog, err := audit.Open(filepath.Join(env.dataDir, "audit.jsonl"))
	if err != nil {
		logger.ErrorContext(ctx, "cannot open the audit log", slog.Any("error", err))
		return exitFailed
	}
	defer func() { _ = auditLog.Close() }()

	cred, created, err := provision.Ensure(ctx, provision.Config{
		ProxyURL:        "ws" + strings.TrimPrefix(env.supervisorURL, "http") + "/core/websocket",
		SupervisorToken: env.supervisorToken,
		CoreURL:         coreURL,
		CredentialPath:  filepath.Join(env.dataDir, "core-credential.json"),
		Audit:           auditLog,
		Logger:          logger,
	})
	if err != nil {
		logger.ErrorContext(ctx, "provisioning failed", slog.Any("error", err))
		return exitFailed
	}
	logger.InfoContext(ctx, "home assistant user is ready",
		slog.String("user_id", cred.UserID), slog.Bool("created", created))
	return exitOK
}
