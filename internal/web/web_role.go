package web

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/session"
)

// panelRoleMiddleware runs for both registered routes and NoRoute, preventing
// static files, login, WebSocket upgrades and the SPA fallback from serving UI
// on a slave. The role is read per request so a later successful pairing takes
// effect without rebuilding the router. Proxy runtimes and subscriptions are
// served independently and are not changed here.
func (s *Server) panelRoleMiddleware(basePath string) gin.HandlerFunc {
	apiPrefix := strings.TrimRight(basePath, "/") + "/panel/api/"
	return func(c *gin.Context) {
		role, err := s.settingService.GetPanelRole()
		if err != nil {
			logger.Error("Cannot read panel role:", err)
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		if role == service.PanelRoleSlave {
			session.DisableSessionLogin(c)
			// FullPath is the registered Gin pattern, not an untrusted URL prefix.
			// API handlers retain their existing bearer/mTLS auth and scope checks.
			if !strings.HasPrefix(c.FullPath(), apiPrefix) {
				c.Header("Cache-Control", "no-store")
				c.AbortWithStatus(http.StatusNotFound)
				return
			}
		}
		c.Next()
	}
}
