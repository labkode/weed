package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// The [oidc] login gives browsers WLCG tokens: the user logs in at the identity
// provider, which must also be a token issuer (tokens.issuers), and gets the access
// token it issues, to use as a bearer token with any client. weed keeps nothing:
// what a login needs between leaving for the provider and coming back (the OAuth2
// state and the PKCE verifier) is in a cookie of the browser.

// oidcLoginTTL is how long a browser has to log in at the provider
const oidcLoginTTL = 10 * time.Minute

var (
	// ErrOIDCState is a callback that does not belong to a login this browser started
	ErrOIDCState = errors.New("this login was not started by this browser, or took too long")
	// ErrOIDCRefused is a login that the identity provider refused
	ErrOIDCRefused = errors.New("the identity provider refused the login")
)

// OIDCConfig configures the [oidc] login
type OIDCConfig struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	Scopes                                      []string
	Audience                                    string // asked for if not empty
}

// IssuedToken is an access token that an OIDC login obtained, as weed accepts it
type IssuedToken struct {
	Token    string
	Issuer   string
	Subject  string
	Username string // the account weed serves it as
	Scopes   []string
	Groups   []string
	Expiry   time.Time
}

// InitializeOIDC finds the provider's endpoints. Credentials must be set: the
// provider must be one of their token issuers.
func (as *AuthStore) InitializeOIDC(ctx context.Context, c OIDCConfig) error {
	if _, ok := as.Credentials().TokenIssuers[c.Issuer]; !ok {
		return fmt.Errorf("oidc.issuer %q is not in tokens.issuers: weed would not accept the tokens it gives out", c.Issuer)
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, as.tokenHTTPClient()), c.Issuer)
	if err != nil {
		return err
	}
	as.oidc = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       c.Scopes,
	}
	as.oidcAudience = c.Audience
	return nil
}

// OIDCLoginCookie names the cookie of a login in progress. Browsers only accept a
// "__Host-" cookie set over HTTPS by this host, so other hosts of the domain cannot
// plant one to make a user complete their login.
func OIDCLoginCookie(secure bool) string {
	if secure {
		return "__Host-weed_oidc_login"
	}
	return "weed_oidc_login"
}

// StartOIDCLogin returns the provider's login page for a new login, and the cookie
// that keeps the login in the browser
func (as *AuthStore) StartOIDCLogin(secure bool) (string, *http.Cookie) {
	state, verifier := randomString(16), oauth2.GenerateVerifier()
	authURL := as.oidc.AuthCodeURL(state, append(as.oidcParams(), oauth2.S256ChallengeOption(verifier))...)
	return authURL, &http.Cookie{
		Name:     OIDCLoginCookie(secure),
		Value:    state + "." + verifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcLoginTTL.Seconds()),
	}
}

// oidcParams are the parameters added to authorization and token requests
func (as *AuthStore) oidcParams() []oauth2.AuthCodeOption {
	if as.oidcAudience == "" {
		return nil
	}
	// INDIGO IAM's parameter for audience-restricted tokens
	return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("audience", as.oidcAudience)}
}

// FinishOIDCLogin completes a login when the provider sends the browser back with
// query: login is the value of the browser's login cookie. The access token must be
// one that weed accepts.
func (as *AuthStore) FinishOIDCLogin(ctx context.Context, login string, query url.Values) (*IssuedToken, error) {
	state, verifier, ok := strings.Cut(login, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(state), []byte(query.Get("state"))) != 1 {
		return nil, ErrOIDCState
	}
	// Only now, so that nobody can make weed show a page with their own text
	if e := query.Get("error"); e != "" {
		return nil, fmt.Errorf("%w: %s %s", ErrOIDCRefused, e, query.Get("error_description"))
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, as.tokenHTTPClient())
	opts := append(as.oidcParams(), oauth2.VerifierOption(verifier))
	t, err := as.oidc.Exchange(ctx, query.Get("code"), opts...)
	if err != nil {
		return nil, fmt.Errorf("cannot get a token for the authorization code: %w", err)
	}
	if !IsJWT(t.AccessToken) {
		return nil, errors.New("the provider's access token is not a JWT")
	}
	v, err := as.verifyToken(t.AccessToken, time.Now())
	if err != nil {
		return nil, fmt.Errorf("weed does not accept the provider's access token: %w", err)
	}
	username, err := v.issuer.username(v.claims.Subject, v.groups)
	if err != nil {
		return nil, err
	}
	if as.UnixUsers {
		if _, err := as.unixUser(username); err != nil {
			return nil, err
		}
	}
	return &IssuedToken{
		Token:    t.AccessToken,
		Issuer:   v.issuer.Issuer,
		Subject:  v.claims.Subject,
		Username: username,
		Scopes:   v.scopes,
		Groups:   v.groups,
		Expiry:   v.claims.Expiry.Time(),
	}, nil
}

// IsForbidden reports whether err is about valid credentials that do not allow
// something
func IsForbidden(err error) bool {
	return errors.Is(err, errForbidden)
}
