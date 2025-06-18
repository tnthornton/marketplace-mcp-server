package auth

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/browser"
)

const (
	// Upbound authentication endpoints
	AuthDomain = "accounts.upbound.io"
	APIDomain  = "api.upbound.io"

	// Authentication paths
	WebLoginPath     = "/login"
	IssueEndpoint    = "/v1/issueTOTP"
	ExchangeEndpoint = "/v1/checkTOTP"
	TOTPDisplayPath  = "/cli/loginCode"
	LoginResultPath  = "/cli/loginResult"

	// Local server for callback
	CallbackPath = "/"
)

// Config represents authentication configuration
type Config struct {
	Domain   string
	APIHost  string
	AuthHost string
}

// Manager handles Upbound authentication using callback-based TOTP flow
type Manager struct {
	config       *Config
	server       *http.Server
	token        chan string
	redirect     chan string
	port         int
	sessionToken string
}

// Token represents an authentication token
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// NewManager creates a new authentication manager
func NewManager() *Manager {
	config := &Config{
		Domain:   "upbound.io",
		APIHost:  APIDomain,
		AuthHost: AuthDomain,
	}

	return &Manager{
		config:   config,
		token:    make(chan string, 1),
		redirect: make(chan string, 1),
	}
}

// Login initiates the Upbound authentication flow using callback mechanism
func (m *Manager) Login(ctx context.Context) (*Token, error) {
	// Start local callback server
	if err := m.startCallbackServer(); err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	defer m.stopCallbackServer()

	// Build authentication URL
	authURL := m.buildAuthURL()

	// Open browser to authentication URL
	log.Printf("Opening browser for authentication: %s", authURL)
	if err := browser.OpenURL(authURL); err != nil {
		log.Printf("Failed to open browser automatically. Please visit: %s", authURL)
	}

	// Wait for callback or timeout
	select {
	case totpCode := <-m.token:
		// Exchange TOTP code for session token
		sessionToken, err := m.exchangeTOTPForSession(ctx, totpCode)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange TOTP for session: %w", err)
		}

		m.sessionToken = sessionToken

		// Send success redirect
		resultURL := m.buildResultURL(true, "")
		m.redirect <- resultURL

		return &Token{
			AccessToken: sessionToken,
			TokenType:   "Session",
		}, nil

	case <-ctx.Done():
		return nil, fmt.Errorf("authentication timeout: %w", ctx.Err())
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authentication timeout")
	}
}

// GetToken returns the current session token
func (m *Manager) GetToken() *Token {
	if m.sessionToken == "" {
		return nil
	}
	return &Token{
		AccessToken: m.sessionToken,
		TokenType:   "Session",
	}
}

// RefreshToken is not applicable for session-based auth
func (m *Manager) RefreshToken(ctx context.Context) (*Token, error) {
	return nil, fmt.Errorf("session token refresh not supported, please re-authenticate")
}

// buildAuthURL constructs the authentication URL following UP CLI pattern
func (m *Manager) buildAuthURL() string {
	// Build callback URL
	callbackURL := fmt.Sprintf("http://localhost:%d%s", m.port, CallbackPath)

	// Build TOTP issue endpoint
	issueURL := url.URL{
		Scheme: "https",
		Host:   m.config.APIHost,
		Path:   IssueEndpoint,
	}
	issueParams := url.Values{
		"returnTo": []string{callbackURL},
	}
	issueURL.RawQuery = issueParams.Encode()

	// Build login endpoint
	loginURL := url.URL{
		Scheme: "https",
		Host:   m.config.AuthHost,
		Path:   WebLoginPath,
	}
	loginParams := url.Values{
		"returnTo": []string{issueURL.String()},
	}
	loginURL.RawQuery = loginParams.Encode()

	return loginURL.String()
}

// buildResultURL constructs the result URL
func (m *Manager) buildResultURL(success bool, errorMsg string) string {
	resultURL := url.URL{
		Scheme: "https",
		Host:   m.config.AuthHost,
		Path:   LoginResultPath,
	}

	if !success && errorMsg != "" {
		params := url.Values{
			"message": []string{errorMsg},
		}
		resultURL.RawQuery = params.Encode()
	}

	return resultURL.String()
}

// exchangeTOTPForSession exchanges TOTP code for session token
func (m *Manager) exchangeTOTPForSession(ctx context.Context, totpCode string) (string, error) {
	if totpCode == "" {
		return "", fmt.Errorf("failed to receive TOTP code from web login")
	}

	// Build exchange URL
	exchangeURL := url.URL{
		Scheme: "https",
		Host:   m.config.APIHost,
		Path:   ExchangeEndpoint,
	}
	params := url.Values{
		"totp": []string{totpCode},
	}
	exchangeURL.RawQuery = params.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exchangeURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Make request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed with status %d", res.StatusCode)
	}

	// Extract session cookie
	for _, cookie := range res.Cookies() {
		if cookie.Name == "SID" {
			return cookie.Value, nil
		}
	}

	return "", fmt.Errorf("no session cookie found in response")
}

// startCallbackServer starts the local HTTP server for callback
func (m *Manager) startCallbackServer() error {
	port, err := m.getAvailablePort()
	if err != nil {
		return err
	}
	m.port = port

	mux := http.NewServeMux()
	mux.HandleFunc(CallbackPath, m.handleCallback)

	m.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", m.port),
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Callback server error: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)
	return nil
}

// stopCallbackServer stops the local HTTP server
func (m *Manager) stopCallbackServer() {
	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.server.Shutdown(ctx)
	}
}

// handleCallback handles the callback from authentication
func (m *Manager) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract TOTP code from query parameters
	totpCode := r.URL.Query().Get("totp")

	// Send the TOTP code
	m.token <- totpCode

	// Wait for redirect URL
	redirectURL := <-m.redirect

	// Redirect to result page
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// getAvailablePort finds an available port
func (m *Manager) getAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(portString)
}

// GetAuthenticatedClient returns an HTTP client with authentication
func (m *Manager) GetAuthenticatedClient(ctx context.Context) *http.Client {
	return &http.Client{
		Transport: &authenticatedTransport{
			sessionToken: m.sessionToken,
			transport:    http.DefaultTransport,
		},
	}
}

// authenticatedTransport adds session authentication to requests
type authenticatedTransport struct {
	sessionToken string
	transport    http.RoundTripper
}

func (t *authenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.sessionToken != "" {
		// Add session cookie
		req.AddCookie(&http.Cookie{
			Name:  "SID",
			Value: t.sessionToken,
		})
	}
	return t.transport.RoundTrip(req)
}
