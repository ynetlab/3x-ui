package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
	"github.com/mhsanaei/3x-ui/v3/internal/web/middleware"
	"github.com/mhsanaei/3x-ui/v3/internal/web/network"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
)

// The control router establishes this context only after binding and verifying
// the master identity. Public panel requests retain the configured Host rule,
// including requests that merely present a bearer token or a TLS certificate.
func controlDomainValidator(domain string) gin.HandlerFunc {
	validate := middleware.DomainValidatorMiddleware(domain)
	return func(c *gin.Context) {
		if peer, ok := cluster.AuthenticatedPeer(c.Request.Context()); ok && peer.Role == cluster.RoleMaster {
			c.Next()
			return
		}
		validate(c)
	}
}

func (s *Server) startControl(panelHandler http.Handler) error {
	config, err := s.settingService.GetControlConfig()
	if err != nil {
		return err
	}
	if !config.Enabled {
		return nil
	}
	pairing := &service.PairingService{}
	pending, err := pairing.IsPendingSlaveInstall()
	if err != nil {
		return err
	}
	var credentials cluster.Credentials
	if !pending {
		credentials, err = s.settingService.EnsureControlCredentials()
		if err != nil {
			allowed, recoveryErr := pairing.CanStartControlWithoutIdentity()
			if recoveryErr != nil || !allowed {
				return fmt.Errorf("load control identity: %w", err)
			}
			credentials = cluster.Credentials{}
		}
	}
	tlsConfig, err := pairing.ControlTLSConfig(credentials)
	if err != nil {
		return err
	}
	basePath, err := s.settingService.GetBasePath()
	if err != nil {
		return err
	}
	auth := cluster.Authorizer{Self: s.settingService.ControlIdentity, LookupPeer: s.settingService.LookupControlPeer}
	router := cluster.NewRouter(auth)
	(&service.AccessLogService{}).RegisterControlRoutes(router)
	(&service.NodeIPService{}).RegisterControlRoutes(router)
	pairing.RegisterControlRoutes(router, func(token string) bool {
		row, ok := (&panel.ApiTokenService{}).MatchToken(token)
		return ok && row.Scope == model.ApiScopeAdmin
	})
	// Reuse the API handlers without creating a second controller tree or
	// scheduling duplicate jobs. Every management call first passes mTLS and
	// the bound-master gate; browser cookies and bearer tokens alone cannot.
	apiPrefix := strings.TrimRight(basePath, "/") + "/panel/api/"
	router.HandleMaster(apiPrefix, panelHandler)
	listener, err := (&net.ListenConfig{}).Listen(s.ctx, "tcp", net.JoinHostPort(config.Listen, strconv.Itoa(config.Port)))
	if err != nil {
		return fmt.Errorf("listen on control port: %w", err)
	}
	s.controlListener = tls.NewListener(listener, tlsConfig)
	s.controlServer = &http.Server{
		Handler:           http.MaxBytesHandler(router, 10<<20),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	go network.ServeHTTP(s.controlServer, s.controlListener, "Control server")
	logger.Info("Control server running HTTPS on", s.controlListener.Addr())
	return nil
}

func (s *Server) stopControl() error {
	var err error
	if s.controlServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = s.controlServer.Shutdown(ctx)
		cancel()
	}
	if s.controlListener != nil {
		if closeErr := s.controlListener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = common.Combine(err, closeErr)
		}
	}
	return err
}
