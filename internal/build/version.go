// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package build carries the version of the running binary.
package build

// Version is the release this binary was built as. A release build sets it
// with -ldflags "-X github.com/SukramJ/ha-airlock/internal/build.Version=…";
// every other build reports the development placeholder.
var Version = "0.0.0-dev"
