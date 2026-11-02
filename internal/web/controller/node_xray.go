package controller

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/runtime"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

// forwardNodeXray intercepts explicitly targeted requests after auth and CSRF.
// Without nodeId all existing local handlers keep their original behavior.
func (a *APIController) forwardNodeXray(c *gin.Context) {
	values, targeted := c.Request.URL.Query()["nodeId"]
	if !targeted {
		c.Next()
		return
	}
	fail := func(status int, message string) {
		c.AbortWithStatusJSON(status, gin.H{"success": false, "msg": message, "obj": nil})
	}
	if len(values) != 1 {
		fail(http.StatusBadRequest, "invalid target node")
		return
	}
	id, err := strconv.Atoi(values[0])
	if err != nil || id <= 0 {
		fail(http.StatusBadRequest, "invalid target node")
		return
	}
	// A node-admin may edit this panel but must never pivot through its stored
	// credentials to another panel. Only the master's admin/session may dispatch.
	if scope, ok := c.Get("api_token_scope"); ok && scope != model.ApiScopeAdmin {
		fail(http.StatusForbidden, "this API token cannot forward requests to another node")
		return
	}
	path := nodeXrayRequestPath(c)
	if !runtime.NodeXrayEndpoint(c.Request.Method, path) {
		fail(http.StatusBadRequest, "endpoint is not available for node Xray editing")
		return
	}
	node, err := (&service.NodeService{}).GetById(id)
	if err != nil {
		fail(http.StatusNotFound, "target node not found")
		return
	}
	if !node.Enable {
		fail(http.StatusBadRequest, "target node is disabled")
		return
	}
	mgr := runtime.GetManager()
	if mgr == nil {
		fail(http.StatusServiceUnavailable, "runtime manager not initialised")
		return
	}
	remote, err := mgr.RemoteFor(node)
	if err != nil {
		fail(http.StatusBadGateway, err.Error())
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "invalid configuration form")
		return
	}
	response, err := remote.XrayRequest(c.Request.Context(), c.Request.Method, path, c.Request.URL.Query(), c.Request.PostForm)
	if err != nil {
		fail(http.StatusBadGateway, err.Error())
		return
	}
	c.Abort()
	c.JSON(http.StatusOK, response)
}

// Resolve only the parameters used by the existing Xray routes. The runtime
// allowlist checks their concrete values before a request reaches another panel.
func nodeXrayRequestPath(c *gin.Context) string {
	path := relAPIPath(c.FullPath())
	for _, key := range []string{"action", "id"} {
		path = strings.ReplaceAll(path, ":"+key, c.Param(key))
	}
	return path
}
