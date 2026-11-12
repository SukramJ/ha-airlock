// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/oauth"
)

// metadataServer serves one document per path over TLS and returns the
// server and a fetcher that trusts it.
func metadataServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *oauth.Fetcher) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, oauth.NewTestFetcher(roots)
}

func fetch(t *testing.T, f *oauth.Fetcher, clientID string) (oauth.ClientMetadata, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f.Fetch(ctx, clientID)
}

func TestFetchAcceptsAValidDocument(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	srv, f := metadataServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"client_id":"`+srv.URL+r.URL.Path+`","client_name":"Example Client",
			"redirect_uris":["http://127.0.0.1:3000/callback","https://app.example/cb"],"token_endpoint_auth_method":"none"}`)
	})

	meta, err := fetch(t, f, srv.URL+"/client.json")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if meta.ClientName != "Example Client" || len(meta.RedirectURIs) != 2 || meta.ClientID != srv.URL+"/client.json" {
		t.Fatalf("metadata = %+v", meta)
	}
}

func TestFetchRejectsDocumentsThatBreakTheRules(t *testing.T) {
	t.Parallel()
	docs := map[string]string{
		"another client id":   `{"client_id":"https://other.example/client.json","client_name":"X","redirect_uris":["https://a.example/cb"]}`,
		"no client name":      `{"client_id":"SELF","redirect_uris":["https://a.example/cb"]}`,
		"no redirect URIs":    `{"client_id":"SELF","client_name":"X","redirect_uris":[]}`,
		"plain http redirect": `{"client_id":"SELF","client_name":"X","redirect_uris":["http://app.example/cb"]}`,
		"custom scheme":       `{"client_id":"SELF","client_name":"X","redirect_uris":["myapp://cb"]}`,
		"client secret":       `{"client_id":"SELF","client_name":"X","redirect_uris":["https://a.example/cb"],"client_secret":"s"}`,
		"confidential client": `{"client_id":"SELF","client_name":"X","redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"not JSON":            `<html>`,
	}
	for name, doc := range docs {
		var srv *httptest.Server
		srv, f := metadataServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, strings.ReplaceAll(doc, "SELF", srv.URL+r.URL.Path))
		})
		if _, err := fetch(t, f, srv.URL+"/client.json"); !errors.Is(err, oauth.ErrInvalidClient) {
			t.Errorf("%s: %v, want invalid_client", name, err)
		}
	}
}

func TestFetchRejectsClientIDsThatAreNotProperURLs(t *testing.T) {
	t.Parallel()
	_, f := metadataServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("a request was made for a client id that must be refused before fetching")
	})
	for _, clientID := range []string{
		"http://client.example/metadata.json",
		"https://client.example",
		"https://client.example/",
		"https://client.example/a/../metadata.json",
		"https://client.example/./metadata.json",
		"https://client.example/metadata.json#frag",
		"https://user:pass@client.example/metadata.json",
		"client-123",
		"file:///etc/passwd",
		"",
	} {
		if _, err := fetch(t, f, clientID); !errors.Is(err, oauth.ErrInvalidClient) {
			t.Errorf("client id %q: %v, want invalid_client", clientID, err)
		}
	}
}

func TestFetchDoesNotFollowRedirectsOrAcceptErrorsOrOversizedDocuments(t *testing.T) {
	t.Parallel()
	cases := map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://internal.example/secret", http.StatusFound)
		},
		"not found": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"client_name":"`+strings.Repeat("x", 70<<10)+`"}`)
		},
	}
	for name, handler := range cases {
		srv, f := metadataServer(t, handler)
		if _, err := fetch(t, f, srv.URL+"/client.json"); !errors.Is(err, oauth.ErrInvalidClient) {
			t.Errorf("%s: %v, want invalid_client", name, err)
		}
	}
}

// The production fetcher must not reach a server on this machine, however
// valid the document it would serve.
func TestProductionFetcherRefusesToConnectToALocalAddress(t *testing.T) {
	t.Parallel()
	reached := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	t.Cleanup(srv.Close)

	_, err := fetch(t, oauth.NewFetcher(), srv.URL+"/client.json")

	if !errors.Is(err, oauth.ErrInvalidClient) || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("error = %v, want a refusal to connect", err)
	}
	if reached {
		t.Fatal("the local server was reached")
	}
}

func TestOnlyPublicAddressesCountAsPublic(t *testing.T) {
	t.Parallel()
	private := []string{
		"127.0.0.1", "127.8.8.8", "10.0.0.1", "172.16.0.1", "172.30.32.2", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "192.0.2.1",
		"198.18.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:192.168.1.1",
		"::ffff:127.0.0.1", "64:ff9b::c0a8:101", "2001:db8::1",
	}
	for _, s := range private {
		if oauth.IsPublicAddress(netip.MustParseAddr(s)) {
			t.Errorf("%s counts as public", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "2606:4700:4700::1111"} {
		if !oauth.IsPublicAddress(netip.MustParseAddr(s)) {
			t.Errorf("%s does not count as public", s)
		}
	}
}

func TestMatchRedirectIsExactExceptForTheLoopbackPort(t *testing.T) {
	t.Parallel()
	registered := []string{"http://127.0.0.1:3000/callback", "http://localhost/cb", "https://app.example/cb"}
	accepted := []string{
		"http://127.0.0.1:3000/callback", "http://127.0.0.1:51234/callback", "http://127.0.0.1/callback",
		"http://localhost:8080/cb", "https://app.example/cb",
	}
	refused := []string{
		"http://127.0.0.1:3000/other", "http://127.0.0.1:3000/callback?x=1", "http://127.0.0.2:3000/callback",
		"http://localhost:3000/callback", "https://app.example/cb/", "https://app.example:8443/cb",
		"https://app.example/cb?next=evil", "https://evil.example/cb", "http://app.example/cb",
		"http://user@127.0.0.1:3000/callback", "",
	}
	for _, uri := range accepted {
		if !oauth.MatchRedirect(registered, uri) {
			t.Errorf("%q was refused", uri)
		}
	}
	for _, uri := range refused {
		if oauth.MatchRedirect(registered, uri) {
			t.Errorf("%q was accepted", uri)
		}
	}
}

// A redirect must not be followed even when its target would serve a
// document that is valid for the requested client id.
func TestFetchDoesNotFollowARedirectToAValidDocument(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	srv, f := metadataServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/client.json" {
			http.Redirect(w, r, "/elsewhere.json", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, `{"client_id":"`+srv.URL+`/client.json","client_name":"X","redirect_uris":["https://a.example/cb"]}`)
	})

	if _, err := fetch(t, f, srv.URL+"/client.json"); !errors.Is(err, oauth.ErrInvalidClient) {
		t.Fatalf("fetch: %v, want invalid_client", err)
	}
}

// The port may vary for a loopback redirect only, whatever was registered.
func TestMatchRedirectKeepsThePortOfAHostThatIsNotLoopback(t *testing.T) {
	t.Parallel()
	registered := []string{"http://app.example:3000/cb", "https://app.example:3000/cb"}
	for _, uri := range []string{"http://app.example:4000/cb", "http://app.example/cb", "https://app.example:4000/cb"} {
		if oauth.MatchRedirect(registered, uri) {
			t.Errorf("%q was accepted", uri)
		}
	}
}
