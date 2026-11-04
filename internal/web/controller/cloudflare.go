package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/cloudflare"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

type CloudflareController struct{ dns service.CloudflareDNSService }

func NewCloudflareController(api *gin.RouterGroup) *CloudflareController {
	a := &CloudflareController{}
	g := api.Group("/cloudflare/nodes/:id")
	g.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})
	g.GET("/ip", a.ip)
	g.GET("/records", a.list)
	g.POST("/records", a.create)
	g.POST("/records/:recordId/bind", a.bind)
	g.POST("/records/:recordId/update", a.update)
	g.POST("/records/:recordId/proxied", a.proxied)
	g.POST("/records/:recordId/delete", a.delete)
	return a
}

func (a *CloudflareController) result(c *gin.Context, value any, err error) {
	if err == nil {
		c.JSON(200, gin.H{"success": true, "obj": value})
		return
	}
	status, code := 500, "cloudflare_storage_error"
	var local *service.CloudflareDNSError
	var provider *cloudflare.Error
	obj := gin.H{}
	if errors.As(err, &local) {
		status, code = local.Status, local.Code
		if local.RecordID != "" {
			obj["recordId"] = local.RecordID
		}
	} else if errors.As(err, &provider) {
		status, code = provider.Status, provider.Code
		obj["providerCodes"] = provider.ProviderCodes
		if provider.RetryAfter > 0 {
			c.Header("Retry-After", strconv.Itoa(provider.RetryAfter))
		}
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		status, code = 504, "cloudflare_request_timeout"
	}
	c.JSON(status, gin.H{"success": false, "msg": code, "obj": obj})
}

func (a *CloudflareController) node(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		a.result(c, nil, &service.CloudflareDNSError{Status: 400, Code: "invalid_cloudflare_node"})
		return 0, false
	}
	return id, true
}

func (a *CloudflareController) body(c *gin.Context, value any) bool {
	d := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		a.result(c, nil, &service.CloudflareDNSError{Status: 400, Code: "invalid_cloudflare_request"})
		return false
	}
	return true
}

func (a *CloudflareController) list(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	value, err := a.dns.List(c.Request.Context(), id)
	a.result(c, value, err)
}

func (a *CloudflareController) ip(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	value, err := (&service.NodeIPService{}).Get(c.Request.Context(), id)
	a.result(c, value, err)
}

func (a *CloudflareController) create(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	var req service.DNSRecordInput
	if !a.body(c, &req) {
		return
	}
	value, err := a.dns.Create(c.Request.Context(), id, req)
	a.result(c, value, err)
}

func (a *CloudflareController) bind(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if !a.body(c, &req) {
		return
	}
	value, err := a.dns.Bind(c.Request.Context(), id, c.Param("recordId"), req.Content)
	a.result(c, value, err)
}

func (a *CloudflareController) update(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	var req service.DNSRecordInput
	if !a.body(c, &req) {
		return
	}
	value, err := a.dns.Update(c.Request.Context(), id, c.Param("recordId"), req)
	a.result(c, value, err)
}

func (a *CloudflareController) proxied(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	var req struct {
		Proxied *bool `json:"proxied"`
	}
	if !a.body(c, &req) {
		return
	}
	if req.Proxied == nil {
		a.result(c, nil, &service.CloudflareDNSError{Status: 400, Code: "invalid_cloudflare_request"})
		return
	}
	value, err := a.dns.SetProxied(c.Request.Context(), id, c.Param("recordId"), *req.Proxied)
	a.result(c, value, err)
}

func (a *CloudflareController) delete(c *gin.Context) {
	id, ok := a.node(c)
	if !ok {
		return
	}
	err := a.dns.Delete(c.Request.Context(), id, c.Param("recordId"))
	a.result(c, nil, err)
}
