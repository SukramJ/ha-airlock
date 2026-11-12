// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Command ha-airlock is the MCP server and the composition root of the
// module. So far it reports its version and, as "ha-airlock probe", measures
// from inside the App container which ways to Home Assistant Core are open;
// CONCEPT.md describes what it is meant to become.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SukramJ/ha-airlock/internal/build"
	"github.com/SukramJ/ha-airlock/internal/probe"
)

// environment is what the process takes from its surroundings. The names
// under which an App reaches the Supervisor and Core are the ones the
// Supervisor writes into the App's hosts file.
type environment struct {
	supervisorURL   string
	supervisorToken string
	coreHost        string
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

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	switch args[0] {
	case "probe":
		return runProbe(ctx, env, logger)
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
