// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Command ha-airlock is the MCP server and the composition root of the
// module. It only reports its version so far; CONCEPT.md describes what it
// is meant to become.
package main

import (
	"fmt"
	"os"

	"github.com/SukramJ/ha-airlock/internal/build"
)

func main() {
	if _, err := fmt.Fprintf(os.Stdout, "ha-airlock %s\n", build.Version); err != nil {
		os.Exit(1)
	}
}
