// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package supervisor asks the Home Assistant Supervisor what ha-airlock
// needs to know about its surroundings.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// CoreURL returns Core's base URL as seen from an App container: the given
// host with the scheme and port the Supervisor reports. Neither is assumed.
func CoreURL(ctx context.Context, supervisorURL, token, coreHost string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, supervisorURL+"/core/info", http.NoBody)
	if err != nil {
		return "", fmt.Errorf("supervisor core info: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("supervisor core info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("supervisor core info: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("supervisor core info: status %d", resp.StatusCode)
	}
	var info struct {
		Result string `json:"result"`
		Data   struct {
			Port int  `json:"port"`
			SSL  bool `json:"ssl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("supervisor core info: %w", err)
	}
	if info.Result != "ok" || info.Data.Port == 0 {
		return "", errors.New("supervisor core info: the answer carries no result ok with a port")
	}
	scheme := "http"
	if info.Data.SSL {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(coreHost, strconv.Itoa(info.Data.Port)), nil
}
