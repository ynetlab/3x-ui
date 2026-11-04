package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
)

func pairingJSON(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		status := http.StatusInternalServerError
		var pe *PairingError
		if errors.As(err, &pe) {
			status = pe.Status
		} else if database.IsNotFound(err) {
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "msg": pairingFailureCode(err)})
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}

func readPairingJSON(w http.ResponseWriter, r *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return pairingError(400, "invalid_pairing_request")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return pairingError(400, "invalid_pairing_request")
	}
	return nil
}

func (s *PairingService) RegisterControlRoutes(router *cluster.Router, isAdmin func(string) bool) {
	registerCertificateControlRoutes(router, isAdmin)
	registerIdentityControlRoutes(router)
	registerCAControlRoutes(router, isAdmin)
	router.HandleBootstrap("POST /cluster/v1/enroll", s.VerifyEnrollmentToken, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request cluster.EnrollRequest
		if err := readPairingJSON(w, r, &request); err != nil {
			pairingJSON(w, nil, err)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		result, err := s.Enroll(token, request)
		pairingJSON(w, result, err)
	}))
	// Pending enrollment identities do not gain the permanent slave-reporting
	// trust until registration commits. These two routes bind their own task.
	self := (&SettingService{}).ControlIdentity
	for _, operation := range []string{"register", "complete"} {
		op := operation
		router.Handle("POST /cluster/v1/pairings/{id}/"+op, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			auth := cluster.Authorizer{Self: self, LookupPeer: func(ctx context.Context, guid string) (cluster.Peer, error) { return s.EnrollmentPeer(ctx, id, guid) }}
			auth.RequireSlave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if op == "register" {
					var request cluster.RegisterRequest
					if err := readPairingJSON(w, r, &request); err != nil {
						pairingJSON(w, nil, err)
						return
					}
					result, err := s.Register(r.Context(), id, request)
					pairingJSON(w, result, err)
				} else {
					result, err := s.Complete(r.Context(), id)
					pairingJSON(w, result, err)
				}
			})).ServeHTTP(w, r)
		}))
	}
	// A staged certificate can serve this proof only. It does not grant the
	// pending master access to normal management routes or disable the UI.
	router.Handle("POST "+cluster.PairingProbePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		row, secrets, err := s.PendingJoin()
		if err != nil {
			pairingJSON(w, nil, pairingError(403, "no_pending_pairing_probe"))
			return
		}
		_, _, identity, err := secrets.Credentials.Load()
		if err != nil {
			pairingJSON(w, nil, err)
			return
		}
		auth := cluster.Authorizer{
			Self: func() (cluster.Identity, error) { return identity, nil },
			LookupPeer: func(_ context.Context, guid string) (cluster.Peer, error) {
				if guid != row.MasterGUID {
					return cluster.Peer{}, cluster.ErrPeerNotTrusted
				}
				return secrets.Request.Profile.Master, nil
			},
		}
		auth.RequireMaster(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request cluster.ProbeRequest
			if err := readPairingJSON(w, r, &request); err != nil {
				pairingJSON(w, nil, err)
				return
			}
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || isAdmin == nil || !isAdmin(token) {
				pairingJSON(w, nil, pairingError(403, "full_admin_token_required"))
				return
			}
			if request.EnrollmentID != row.EnrollmentID || len(request.Challenge) < 16 || len(request.Challenge) > 256 {
				pairingJSON(w, nil, pairingError(400, "invalid_pairing_probe"))
				return
			}
			pairingJSON(w, cluster.ProbeResponse{GUID: identity.GUID, Role: cluster.RoleSlave, Challenge: request.Challenge}, nil)
		})).ServeHTTP(w, r)
	}))
}

// ControlTLSConfig selects a staged leaf only for a marked pairing probe.
// Every normal connection loads the active credential. This lets an installed
// master keep its UI and current control identity until registration succeeds.
func (s *PairingService) ControlTLSConfig(fallback cluster.Credentials) (*tls.Config, error) {
	var config *tls.Config
	if fallback.CertPEM == "" {
		pending, err := s.CanStartControlWithoutIdentity()
		if err != nil {
			return nil, err
		}
		if !pending {
			return nil, pairingError(500, "control_identity_required")
		}
		config = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		var err error
		config, err = cluster.ServerTLS(fallback)
		if err != nil {
			return nil, err
		}
	}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, protocol := range hello.SupportedProtos {
			if protocol == cluster.PairingALPN {
				_, secrets, err := s.PendingJoin()
				if err != nil {
					return nil, err
				}
				staged, err := cluster.ServerTLS(secrets.Credentials)
				if err != nil {
					return nil, err
				}
				staged.NextProtos = []string{"http/1.1"}
				return staged, nil
			}
		}
		credentials, err := (&SettingService{}).controlServerCredentials(hello.SupportedProtos)
		if err != nil {
			return nil, err
		}
		return cluster.ServerTLS(credentials)
	}
	return config, nil
}
