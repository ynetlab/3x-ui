package controller

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"io"
	"net/http"
)

func NewControlPKIController(api *gin.RouterGroup) {
	g := api.Group("/control-pki")
	g.Use(func(c *gin.Context) { c.Header("Cache-Control", "no-store"); c.Next() })
	g.GET("/status", func(c *gin.Context) { value, err := service.ControlCertificateStatus(); pairingResult(c, value, err) })
	g.POST("/rotate-ca", func(c *gin.Context) {
		var req struct {
			Confirm bool `json:"confirm"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF {
			pairingResult(c, nil, &service.PairingError{Status: 400, Code: "invalid_ca_rotation"})
			return
		}
		value, err := service.RotateControlCA(req.Confirm)
		pairingResult(c, value, err)
	})
}
