package cluster

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type authenticatedPeerKey struct{}

func AuthenticatedPeer(ctx context.Context) (Identity, bool) {
	i, ok := ctx.Value(authenticatedPeerKey{}).(Identity)
	return i, ok
}

// Authorizer resolves current role and trust bindings for every request, so a
// removed peer cannot retain access through a pooled TLS connection.
type Authorizer struct {
	Self       func() (Identity, error)
	LookupPeer func(context.Context, string) (Peer, error)
}

func (a Authorizer) require(role string, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if a.Self == nil || a.LookupPeer == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		self, err := a.Self()
		if err != nil || self.Validate() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		identity, err := CertificateIdentity(r.TLS.PeerCertificates[0])
		if err != nil || identity.Role != role || identity.GUID == self.GUID || identity.Role == self.Role {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		peer, err := a.LookupPeer(r.Context(), identity.GUID)
		if err != nil || peer.Validate() != nil || matchPeer(r.TLS.PeerCertificates[0], peer) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), authenticatedPeerKey{}, identity)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireMaster permits only a bound master managing this slave.
func (a Authorizer) RequireMaster(handler http.Handler) http.Handler {
	return a.require(RoleMaster, handler)
}

// RequireSlave permits only a bound slave reporting to this master.
func (a Authorizer) RequireSlave(handler http.Handler) http.Handler {
	return a.require(RoleSlave, handler)
}

type BootstrapVerifier func(context.Context, string) error

// Bootstrap separates enrollment-token authentication from established mTLS.
// The pairing step supplies the one-time-token verifier; nil fails closed.
func (a Authorizer) Bootstrap(verify BootstrapVerifier, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if verify == nil || handler == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if a.Self == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		self, err := a.Self()
		if err != nil || self.Validate() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if self.Role != RoleMaster {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := verify(r.Context(), token); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

var ErrPeerNotTrusted = errors.New("control peer is not trusted")

// Router keeps control routes independent of the browser router. New routes
// explicitly select bootstrap, master or slave authentication.
type Router struct {
	mux  *http.ServeMux
	auth Authorizer
}

func NewRouter(auth Authorizer) *Router { return &Router{mux: http.NewServeMux(), auth: auth} }

// Handle is for task-bound authentication, whose peer lookup depends on the
// matched task ID. The supplied handler must enforce its enrollment binding.
func (r *Router) Handle(pattern string, h http.Handler) { r.mux.Handle(pattern, h) }

func (r *Router) HandleBootstrap(pattern string, verify BootstrapVerifier, h http.Handler) {
	r.mux.Handle(pattern, r.auth.Bootstrap(verify, h))
}

func (r *Router) HandleMaster(pattern string, h http.Handler) {
	r.mux.Handle(pattern, r.auth.RequireMaster(h))
}

func (r *Router) HandleSlave(pattern string, h http.Handler) {
	r.mux.Handle(pattern, r.auth.RequireSlave(h))
}
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) { r.mux.ServeHTTP(w, req) }
