// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package provision gives ha-airlock its own Home Assistant user.
//
// On the first start it creates the user through the Supervisor's proxy,
// logs in as that user once, directly at Core, and keeps the refresh token
// that login yields. The password it set is never stored. On every later
// start it finds the stored credential and only checks that Core still
// accepts it.
//
// It creates exactly one user and takes no input from an MCP client. It
// never touches a user it did not create: if a user with its username
// exists and no credential is stored, it stops.
package provision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/hacore"
)

const (
	// Username is the login name of the user ha-airlock creates for itself.
	Username = "ha-airlock"
	// displayName is what Home Assistant shows for that user.
	displayName = "ha-airlock"
	// adminGroup is Core's group of administrators. The diagnostic commands
	// and event subscriptions ha-airlock needs require it.
	adminGroup = "system-admin"

	eventProvisioning = "provisioning"
)

// ErrUserExists reports a Home Assistant user with ha-airlock's username for
// which no credential is stored. ha-airlock did not create it, or lost what
// it created; either way it does not take the user over.
var ErrUserExists = errors.New("a home assistant user named " + Username + " exists, but no credential for it is stored")

// ErrCredentialRefused reports a stored credential that Core no longer
// accepts.
var ErrCredentialRefused = errors.New("home assistant refused the stored credential")

// Credential is what ha-airlock keeps to act as its user.
type Credential struct {
	UserID       string `json:"user_id"`
	RefreshToken string `json:"refresh_token"`
	// ClientID is the client the refresh token was issued to; Core accepts
	// the token only together with it.
	ClientID string `json:"client_id"`
}

// Config is what provisioning needs.
type Config struct {
	// ProxyURL is the WebSocket URL of the Supervisor's proxy to Core.
	ProxyURL string
	// SupervisorToken authenticates against the proxy.
	SupervisorToken string
	// CoreURL is Core's own base URL, without a trailing slash.
	CoreURL string
	// CredentialPath is the file the credential is kept in.
	CredentialPath string
	Audit          *audit.Log
	Logger         *slog.Logger
}

// Ensure returns the credential of ha-airlock's user, creating the user if
// this is the first start. created reports whether it did.
func Ensure(ctx context.Context, cfg Config) (cred Credential, created bool, err error) {
	core := newCoreAuth(cfg.CoreURL)

	cred, err = loadCredential(cfg.CredentialPath)
	switch {
	case err == nil:
		if _, err := core.accessToken(ctx, cred); err != nil {
			return Credential{}, false, err
		}
		return cred, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return Credential{}, false, err
	}

	cred, err = create(ctx, cfg, core)
	if auditErr := record(ctx, cfg.Audit, cred, err); auditErr != nil {
		// An unrecorded provisioning is not a finished one, whatever its
		// own outcome was.
		return Credential{}, false, errors.Join(err, auditErr)
	}
	if err != nil {
		return Credential{}, false, err
	}
	announce(ctx, cfg, core, cred)
	return cred, true, nil
}

// create makes the user, logs in as it and stores the credential. A user it
// created is removed again if any later step fails, so that a failed start
// does not leave a user behind that the next start would refuse to touch.
func create(ctx context.Context, cfg Config, core *coreAuth) (Credential, error) {
	proxy, err := hacore.Dial(ctx, cfg.ProxyURL, cfg.SupervisorToken)
	if err != nil {
		return Credential{}, fmt.Errorf("provision: %w", err)
	}
	defer func() { _ = proxy.Close() }()

	if err := refuseExistingUser(ctx, proxy); err != nil {
		return Credential{}, err
	}

	userID, err := createUser(ctx, proxy)
	if err != nil {
		return Credential{}, err
	}
	cred, err := finish(ctx, cfg, core, proxy, userID)
	if err != nil {
		if delErr := deleteUser(ctx, proxy, userID); delErr != nil {
			cfg.Logger.ErrorContext(ctx, "provisioning failed and the user it created could not be removed",
				slog.String("user_id", userID), slog.Any("error", delErr))
		}
		return Credential{}, err
	}
	return cred, nil
}

// finish is everything after the user exists.
func finish(ctx context.Context, cfg Config, core *coreAuth, proxy *hacore.Conn, userID string) (Credential, error) {
	password, err := randomPassword()
	if err != nil {
		return Credential{}, err
	}
	setPassword := struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		Password string `json:"password"`
	}{UserID: userID, Username: Username, Password: password}
	if err := proxy.Call(ctx, "config/auth_provider/homeassistant/create", setPassword, nil); err != nil {
		return Credential{}, fmt.Errorf("provision: give the user a login: %w", err)
	}

	cred, err := core.login(ctx, Username, password)
	if err != nil {
		return Credential{}, err
	}
	cred.UserID = userID
	if err := storeCredential(cfg.CredentialPath, cred); err != nil {
		return Credential{}, err
	}
	return cred, nil
}

func refuseExistingUser(ctx context.Context, proxy *hacore.Conn) error {
	var users []struct {
		Username string `json:"username"`
	}
	if err := proxy.Call(ctx, "config/auth/list", nil, &users); err != nil {
		return fmt.Errorf("provision: list users: %w", err)
	}
	for _, u := range users {
		if u.Username == Username {
			return ErrUserExists
		}
	}
	return nil
}

func createUser(ctx context.Context, proxy *hacore.Conn) (string, error) {
	params := struct {
		Name      string   `json:"name"`
		GroupIDs  []string `json:"group_ids"`
		LocalOnly bool     `json:"local_only"`
	}{Name: displayName, GroupIDs: []string{adminGroup}, LocalOnly: true}
	var result struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := proxy.Call(ctx, "config/auth/create", params, &result); err != nil {
		return "", fmt.Errorf("provision: create user: %w", err)
	}
	if result.User.ID == "" {
		return "", errors.New("provision: create user: home assistant returned no user id")
	}
	return result.User.ID, nil
}

func deleteUser(ctx context.Context, proxy *hacore.Conn, userID string) error {
	params := struct {
		UserID string `json:"user_id"`
	}{UserID: userID}
	if err := proxy.Call(ctx, "config/auth/delete", params, nil); err != nil {
		return fmt.Errorf("provision: delete user: %w", err)
	}
	return nil
}

// record writes the outcome of a provisioning attempt to the audit log.
func record(ctx context.Context, log *audit.Log, cred Credential, provisionErr error) error {
	entry := audit.Entry{Event: eventProvisioning, Decision: "bootstrap"}
	if provisionErr != nil {
		entry.Result = "failed: " + provisionErr.Error()
	} else {
		entry.Result = "created home assistant user " + cred.UserID
	}
	if _, err := log.Append(ctx, entry); err != nil {
		return fmt.Errorf("provision: record in the audit log: %w", err)
	}
	return nil
}

// announce tells the owner, inside Home Assistant and as the new user, that
// the user was created. The user and its credential exist at this point, so
// a failure here is logged and does not undo them.
func announce(ctx context.Context, cfg Config, core *coreAuth, cred Credential) {
	err := func() error {
		token, err := core.accessToken(ctx, cred)
		if err != nil {
			return err
		}
		conn, err := hacore.Dial(ctx, core.webSocketURL(), token)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()

		const text = "ha-airlock created the Home Assistant user \"" + displayName +
			"\" for itself. Everything ha-airlock does in Home Assistant is done as this user."
		logbook := serviceCall{Domain: "logbook", Service: "log", ServiceData: map[string]string{
			"name": displayName, "message": text,
		}}
		if err := conn.Call(ctx, "call_service", logbook, nil); err != nil {
			return fmt.Errorf("logbook entry: %w", err)
		}
		notification := serviceCall{Domain: "persistent_notification", Service: "create", ServiceData: map[string]string{
			"title": "ha-airlock", "message": text, "notification_id": "ha_airlock_provisioned",
		}}
		if err := conn.Call(ctx, "call_service", notification, nil); err != nil {
			return fmt.Errorf("notification: %w", err)
		}
		return nil
	}()
	if err != nil {
		cfg.Logger.WarnContext(ctx, "the new user could not be announced in home assistant", slog.Any("error", err))
	}
}

// serviceCall is the body of Core's call_service command.
type serviceCall struct {
	Domain      string            `json:"domain"`
	Service     string            `json:"service"`
	ServiceData map[string]string `json:"service_data"`
}

// randomPassword returns 32 random bytes in URL-safe base64.
func randomPassword() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("provision: generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func loadCredential(path string) (Credential, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's configuration, not client input
	if err != nil {
		return Credential{}, fmt.Errorf("read credential: %w", err)
	}
	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return Credential{}, fmt.Errorf("read credential: %w", err)
	}
	if cred.UserID == "" || cred.RefreshToken == "" || cred.ClientID == "" {
		return Credential{}, errors.New("read credential: the file is incomplete")
	}
	return cred, nil
}

// storeCredential writes the credential so that the file is either complete
// or absent, and readable by its owner only.
func storeCredential(path string, cred Credential) error {
	data, err := json.Marshal(cred) //nolint:gosec // storing the refresh token is this function's purpose; the file is 0600
	if err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store credential: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store credential: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	return nil
}
