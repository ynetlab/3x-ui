package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// Certificate issuance is queued; no ACME/DNS propagation wait runs inside a
// browser HTTP request. The worker and status API survive panel restarts.
func NewNodeCertificateController(api *gin.RouterGroup) {
	s := &service.NodeCertificateService{}
	g := api.Group("/certificates")
	g.Use(func(c *gin.Context) { c.Header("Cache-Control", "no-store"); c.Next() })
	result := func(c *gin.Context, value any, err error) {
		if err != nil {
			// Reuse stable provider/status handling without returning raw errors.
			if pe, ok := err.(*service.PairingError); ok {
				pairingResult(c, nil, pe)
				return
			}
			(&CloudflareController{}).result(c, nil, err)
			return
		}
		c.JSON(200, gin.H{"success": true, "obj": value})
	}
	body := func(c *gin.Context, value any) bool {
		d := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10))
		d.DisallowUnknownFields()
		if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
			result(c, nil, &service.PairingError{Status: 400, Code: "invalid_certificate_request"})
			return false
		}
		return true
	}
	g.GET("/settings", func(c *gin.Context) { value, err := s.Config(); result(c, value, err) })
	g.POST("/settings", func(c *gin.Context) {
		var req service.ACMEConfig
		if !body(c, &req) {
			return
		}
		value, err := s.SaveConfig(req)
		result(c, value, err)
	})
	node := func(c *gin.Context) (int, bool) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id < 1 {
			result(c, nil, &service.PairingError{Status: 400, Code: "invalid_certificate_node"})
			return 0, false
		}
		return id, true
	}
	g.GET("/nodes/:id", func(c *gin.Context) {
		id, ok := node(c)
		if !ok {
			return
		}
		value, err := s.Status(c.Request.Context(), id)
		result(c, value, err)
	})
	g.POST("/nodes/:id", func(c *gin.Context) {
		id, ok := node(c)
		if !ok {
			return
		}
		var req service.CertificateRequest
		if !body(c, &req) {
			return
		}
		value, err := s.Request(c.Request.Context(), id, req)
		result(c, value, err)
	})
	g.POST("/nodes/:id/retry", func(c *gin.Context) {
		id, ok := node(c)
		if !ok {
			return
		}
		value, err := s.Retry(c.Request.Context(), id)
		result(c, value, err)
	})
}
