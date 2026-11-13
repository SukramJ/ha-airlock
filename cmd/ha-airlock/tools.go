// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// writeToolsDoc writes the published list of tools, generated from the
// catalogue itself so that it cannot describe a tool that does not exist
// or leave one out.
func writeToolsDoc(w io.Writer) error {
	var b strings.Builder
	b.WriteString("# Tools\n\n")
	b.WriteString("Generated from the tool catalogue by `ha-airlock tools`. Do not edit; a test\n")
	b.WriteString("fails when this file and the catalogue differ.\n\n")
	b.WriteString("Every tool belongs to one risk tier and touches only the Home Assistant\n")
	b.WriteString("endpoints listed for it. There are no other tools, and none can be added\n")
	b.WriteString("at run time.\n\n")
	b.WriteString("| Tool | Tier | What it does | Home Assistant endpoints |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, tool := range catalog.All() {
		endpoints := make([]string, 0, len(tool.Endpoints))
		for _, e := range tool.Endpoints {
			endpoints = append(endpoints, "`"+e+"`")
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", tool.Name, tool.Tier, tool.Description, strings.Join(endpoints, ", "))
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write tools list: %w", err)
	}
	return nil
}
