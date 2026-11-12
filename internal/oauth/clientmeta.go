// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Limits on fetching a client's metadata document. The document is a few
// hundred bytes of JSON; anything slower or larger is not one.
const (
	metadataTimeout = 5 * time.Second
	metadataMaxSize = 64 << 10
)

// ErrInvalidClient reports a client id, or the document behind it, that
// does not meet the rules. It becomes OAuth's invalid_client.
var ErrInvalidClient = errors.New("invalid_client")

// ClientMetadata is what ha-airlock uses of a client's metadata document.
type ClientMetadata struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
}

// Fetcher retrieves Client ID Metadata Documents.
//
// A client names the URL, so the request it causes must not be usable
// against the home network: the fetcher speaks HTTPS only, follows no
// redirect, and refuses, at the moment of connecting, every address that is
// not a public one. Checking at connect time, not at lookup time, also
// covers a name that resolves differently on a second lookup.
type Fetcher struct {
	client *http.Client
}

// NewFetcher returns the fetcher used in production.
func NewFetcher() *Fetcher {
	return newFetcher(isPublicAddress, nil)
}

func newFetcher(allow func(netip.Addr) bool, roots *x509.CertPool) *Fetcher {
	dialer := &net.Dialer{
		Timeout: metadataTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("refusing to connect to %q: %w", address, err)
			}
			if !allow(addrPort.Addr().Unmap()) {
				return fmt.Errorf("refusing to connect to %s: not a public address", addrPort.Addr())
			}
			return nil
		},
	}
	return &Fetcher{client: &http.Client{
		Timeout: metadataTimeout,
		Transport: &http.Transport{
			// No proxy: a proxy would make the connection for us and take
			// the address check out of our hands.
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			TLSHandshakeTimeout:   metadataTimeout,
			ResponseHeaderTimeout: metadataTimeout,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// Fetch retrieves and validates the metadata document of a client id.
func (f *Fetcher) Fetch(ctx context.Context, clientID string) (ClientMetadata, error) {
	if err := validateClientID(clientID); err != nil {
		return ClientMetadata{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, http.NoBody)
	if err != nil {
		return ClientMetadata{}, fmt.Errorf("%w: %w", ErrInvalidClient, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document could not be fetched: %w", ErrInvalidClient, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document was answered with status %d", ErrInvalidClient, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, metadataMaxSize+1))
	if err != nil {
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document could not be read: %w", ErrInvalidClient, err)
	}
	if len(body) > metadataMaxSize {
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document is larger than %d bytes", ErrInvalidClient, metadataMaxSize)
	}
	return parseClientMetadata(clientID, body)
}

// validateClientID applies the rules for a client id that is a URL.
func validateClientID(clientID string) error {
	u, err := url.Parse(clientID)
	if err != nil {
		return fmt.Errorf("%w: the client id is not a URL", ErrInvalidClient)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: the client id must be an https URL", ErrInvalidClient)
	case u.Host == "":
		return fmt.Errorf("%w: the client id has no host", ErrInvalidClient)
	case u.Path == "" || u.Path == "/":
		return fmt.Errorf("%w: the client id must contain a path", ErrInvalidClient)
	case u.Fragment != "" || strings.Contains(clientID, "#"):
		return fmt.Errorf("%w: the client id must not contain a fragment", ErrInvalidClient)
	case u.User != nil:
		return fmt.Errorf("%w: the client id must not contain a user or password", ErrInvalidClient)
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: the client id must not contain dot segments", ErrInvalidClient)
		}
	}
	return nil
}

func parseClientMetadata(clientID string, body []byte) (ClientMetadata, error) {
	var doc struct {
		ClientID                string   `json:"client_id"`
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientSecret            *string  `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document is not JSON", ErrInvalidClient)
	}
	switch {
	case doc.ClientID != clientID:
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document names another client id", ErrInvalidClient)
	case strings.TrimSpace(doc.ClientName) == "":
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document has no client_name", ErrInvalidClient)
	case len(doc.RedirectURIs) == 0:
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document has no redirect_uris", ErrInvalidClient)
	case doc.ClientSecret != nil:
		return ClientMetadata{}, fmt.Errorf("%w: the metadata document must not contain a client_secret", ErrInvalidClient)
	case doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none":
		// ha-airlock issues tokens to public clients only.
		return ClientMetadata{}, fmt.Errorf("%w: only token_endpoint_auth_method none is supported", ErrInvalidClient)
	}
	for _, uri := range doc.RedirectURIs {
		if !isAcceptableRedirect(uri) {
			return ClientMetadata{}, fmt.Errorf("%w: redirect URI %q is neither https nor a loopback address", ErrInvalidClient, uri)
		}
	}
	return ClientMetadata{ClientID: doc.ClientID, ClientName: doc.ClientName, RedirectURIs: doc.RedirectURIs}, nil
}

// isAcceptableRedirect reports whether a redirect URI is https, or http on
// a loopback address.
func isAcceptableRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopbackHost(u.Hostname()))
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// MatchRedirect reports whether a redirect URI presented in an
// authorization request is one the client registered. The comparison is
// exact, except that a loopback redirect may differ in its port: a native
// client listens on whatever port it was given.
func MatchRedirect(registered []string, presented string) bool {
	for _, candidate := range registered {
		if candidate == presented {
			return true
		}
		c, errC := url.Parse(candidate)
		p, errP := url.Parse(presented)
		if errC != nil || errP != nil {
			continue
		}
		if c.Scheme == "http" && p.Scheme == "http" &&
			isLoopbackHost(c.Hostname()) && c.Hostname() == p.Hostname() &&
			c.EscapedPath() == p.EscapedPath() && c.RawQuery == p.RawQuery &&
			p.Fragment == "" && p.User == nil {
			return true
		}
	}
	return false
}

// nonPublic are address ranges that are not reachable as public unicast
// addresses, beyond what netip itself classifies.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64: maps onto IPv4
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// isPublicAddress reports whether addr is a public unicast address.
func isPublicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() ||
		addr.IsInterfaceLocalMulticast() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
