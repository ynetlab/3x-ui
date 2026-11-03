package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
)

func registerCertificateControlRoutes(router *cluster.Router, isAdmin func(string) bool) {
	registerCertificateControlRoutesWithRoots(router, isAdmin, nil)
}

func registerCertificateControlRoutesWithRoots(router *cluster.Router, isAdmin func(string) bool, roots *x509.CertPool) {
	for _, op := range []string{"stage", "activate", "confirm", "rollback", "status"} {
		operation := op
		router.Handle("POST /cluster/v1/certificates/"+op, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req CertificateInstallRequest
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
			d.DisallowUnknownFields()
			if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
				pairingJSON(w, nil, pairingError(400, "invalid_certificate_request"))
				return
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
				if !ok || isAdmin == nil || !isAdmin(token) {
					pairingJSON(w, nil, pairingError(403, "full_admin_token_required"))
					return
				}
				peer, ok := cluster.AuthenticatedPeer(r.Context())
				if !ok {
					pairingJSON(w, nil, pairingError(403, "certificate_master_required"))
					return
				}
				result, err := installCertificate(peer.GUID, operation, req, roots)
				pairingJSON(w, result, err)
			})
			settings := &SettingService{}
			auth := cluster.Authorizer{Self: settings.ControlIdentity, LookupPeer: settings.LookupControlPeer}
			if req.EnrollmentID != "" {
				job, secrets, err := (&PairingService{}).PendingJoin()
				if err != nil || job.EnrollmentID != req.EnrollmentID {
					pairingJSON(w, nil, pairingError(403, "no_pending_pairing_certificate"))
					return
				}
				_, _, identity, err := secrets.Credentials.Load()
				if err != nil {
					pairingJSON(w, nil, pairingError(403, "no_pending_pairing_certificate"))
					return
				}
				auth = cluster.Authorizer{Self: func() (cluster.Identity, error) { return identity, nil }, LookupPeer: func(_ context.Context, guid string) (cluster.Peer, error) {
					if guid != job.MasterGUID {
						return cluster.Peer{}, cluster.ErrPeerNotTrusted
					}
					return secrets.Request.Profile.Master, nil
				}}
			}
			auth.RequireMaster(handler).ServeHTTP(w, r)
		}))
	}
}
