/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const (
	defaultGCRHost = "gcr.io"
)

var (
	re                 = regexp.MustCompile(`^/v2/`)
	realm              = regexp.MustCompile(`realm="(.*?)"`)
	service            = regexp.MustCompile(`service="(.*?)"`)
	ctxKeyOriginalHost = struct{}{}
)

type registryConfig struct {
	gcpProject       string
	host             string
	artifactRegistry string
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable not specified")
	}

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		log.Fatal("REGISTRY_HOST environment variable not specified (example: europe-docker.pkg.dev)")
	}
	gcpProject := os.Getenv("GCP_PROJECT")
	if gcpProject == "" {
		log.Fatal("GCP_PROJECT environment variable not specified")
	}
	artifactRegistry := os.Getenv("ARTIFACT_REGISTRY")
	if artifactRegistry == "" {
		log.Fatal("ARTIFACT_REGISTRY environment variable not specified")
	}

	reg := registryConfig{
		gcpProject:       gcpProject,
		host:             registryHost,
		artifactRegistry: artifactRegistry,
	}

	tokenEndpoint, err := discoverTokenService(reg.host)
	if err != nil {
		log.Fatalf("target registry's token endpoint could not be discovered: %+v", err)
	}
	log.Printf("discovered token endpoint for backend registry: %s", tokenEndpoint)

	mux := http.NewServeMux()

	if tokenEndpoint != "" {
		mux.Handle("/_token", tokenProxyHandler(tokenEndpoint, gcpProject, artifactRegistry))
	}
	mux.Handle("/artifacts-downloads/", registryAPIProxy(reg))

	mux.Handle("/v2/", registryAPIProxy(reg))

	addr := ":" + port
	handler := captureHostHeader(mux)
	log.Printf("starting to listen on %s", addr)
	if cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); cert != "" && key != "" {
		err = http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
	}
	if err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}

	log.Printf("server shutdown successfully")
}

func discoverTokenService(registryHost string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query the registry host %s: %+v", registryHost, err)
	}
	hdr := resp.Header.Get("www-authenticate")
	if hdr == "" {
		return "", fmt.Errorf("www-authenticate header not returned from %s, cannot locate token endpoint", url)
	}
	matches := realm.FindStringSubmatch(hdr)
	if len(matches) == 0 {
		return "", fmt.Errorf("cannot locate 'realm' in %s response header www-authenticate: %s", url, hdr)
	}
	return matches[1], nil
}

// captureHostHeader is a middleware to capture Host header in a context key.
func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// tokenProxyHandler proxies the token requests to the specified token service.
// It adjusts the ?scope= parameter in the query from "repository:foo:..." to
// "repository:repoPrefix/foo:.." and reverse proxies the query to the specified
// tokenEndpoint.
func tokenProxyHandler(tokenEndpoint, gcpProject string, artifactRegistry string) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		Director: func(r *http.Request) {
			orig := r.URL.String()

			q := r.URL.Query()
			scope := q.Get("scope")
			if scope != "" {
				newScope := strings.Replace(scope, "repository:", fmt.Sprintf("repository:%s/%s/", gcpProject, artifactRegistry), 1)
				q.Set("scope", newScope)
			}
			u, _ := url.Parse(tokenEndpoint)
			u.RawQuery = q.Encode()
			r.URL = u
			log.Printf("tokenProxyHandler: rewrote url:%s into:%s", orig, r.URL)
			r.Host = u.Host
		},
	}).ServeHTTP
}

// registryAPIProxy returns a reverse proxy to the specified registry.
func registryAPIProxy(cfg registryConfig) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		Director:  rewriteRegistryV2URL(cfg),
		Transport: &registryRoundtripper{},
	}).ServeHTTP
}

// handleRegistryAPIVersion signals docker-registry v2 API on /v2/ endpoint.
func handleRegistryAPIVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	fmt.Fprint(w, "ok")
}

// rewriteRegistryV2URL rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*. It leaves /v2/ as is.
func rewriteRegistryV2URL(c registryConfig) func(*http.Request) {
	return func(req *http.Request) {
		u := req.URL.String()
		req.Host = c.host
		req.URL.Scheme = "https"
		req.URL.Host = c.host
		if req.URL.Path != "/v2/" {
			req.URL.Path = re.ReplaceAllString(req.URL.Path, fmt.Sprintf("/v2/%s/%s/", c.gcpProject, c.artifactRegistry))
		}
		log.Printf("rewrote url: %s into %s", u, req.URL)
	}
}

type registryRoundtripper struct {
	auth authenticator
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("request received. url=%s", req.URL)

	if rrt.auth != nil {
		req.Header.Set("Authorization", rrt.auth.AuthHeader())
	}

	origHost := req.Context().Value(ctxKeyOriginalHost).(string)
	if ua := req.Header.Get("user-agent"); ua != "" {
		req.Header.Set("user-agent", "gcr-proxy/0.1 customDomain/"+origHost+" "+ua)
	}

	// TODO(ahmetb) remove after Google internal bug 129780113 is fixed.
	req.Header.Set("accept", "*/*")

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		log.Printf("request completed (status=%d) url=%s", resp.StatusCode, req.URL)
	} else {
		log.Printf("request failed with error: %+v", err)
		return nil, err
	}
	updateTokenEndpoint(resp, origHost)
	return resp, nil
}

// updateTokenEndpoint modifies the response header like:
//    Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
// to point to the https://host/token endpoint to force using local token
// endpoint proxy.
func updateTokenEndpoint(resp *http.Response, host string) {
	v := resp.Header.Get("www-authenticate")
	if v == "" {
		return
	}
	cur := fmt.Sprintf("https://%s/_token", host)
	r := realm.ReplaceAllString(v, fmt.Sprintf(`realm="%s"`, cur))
	s := service.ReplaceAllString(r, fmt.Sprintf(`service="%s"`, host))
	resp.Header.Set("www-authenticate", s)
}

type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }
