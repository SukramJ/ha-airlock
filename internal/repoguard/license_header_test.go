// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package repoguard_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two lines every Go file in this module carries. The SPDX line is
// what automated licence scanners read; the copyright line names the
// rights holder, which the SPDX identifier alone does not.
const (
	spdxLine      = "// SPDX-License-Identifier: Apache-2.0"
	copyrightLine = "// Copyright (C) 2026 SukramJ."
)

// TestLicenseHeaderOnEveryGoFile walks the module and fails naming every
// .go file that does not carry both header lines ahead of its package
// clause.
//
// The header is checked in the block before `package` rather than on lines
// 1 and 2: a file may legitimately open with a //go:build constraint,
// which must precede the licence comment.
func TestLicenseHeaderOnEveryGoFile(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	var missing []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .git holds no Go source; a vendor tree would hold
			// third-party source carrying its own upstream notice.
			if name := d.Name(); name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		hasSPDX, hasCopyright, herr := headerLines(path)
		if herr != nil {
			return herr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		switch {
		case !hasSPDX && !hasCopyright:
			missing = append(missing, rel+": missing both header lines")
		case !hasSPDX:
			missing = append(missing, rel+": missing "+spdxLine)
		case !hasCopyright:
			missing = append(missing, rel+": missing "+copyrightLine)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	if len(missing) > 0 {
		t.Errorf("%d Go file(s) without a complete licence header:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// headerLines reports whether the comment block preceding the package
// clause contains the SPDX and copyright lines. Scanning stops at
// `package` so a later occurrence of either string — inside a string
// literal, or in a test fixture — cannot satisfy the check.
func headerLines(path string) (hasSPDX, hasCopyright bool, err error) {
	f, err := os.Open(path) //nolint:gosec // walking this module's own tree
	if err != nil {
		return false, false, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "package ") {
			break
		}
		switch line {
		case spdxLine:
			hasSPDX = true
		case copyrightLine:
			hasCopyright = true
		}
	}
	if serr := sc.Err(); serr != nil {
		return false, false, serr
	}
	return hasSPDX, hasCopyright, nil
}

// moduleRoot returns the directory holding go.mod, walking up from the
// test's working directory so the guard covers the whole module however
// `go test` was invoked.
func moduleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}
