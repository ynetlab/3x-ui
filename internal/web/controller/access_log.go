package controller

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

type AccessLogController struct{ logs service.AccessLogService }

func NewAccessLogController(api *gin.RouterGroup) *AccessLogController {
	a := &AccessLogController{}
	g := api.Group("/access-logs")
	g.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		role, err := (&service.SettingService{}).GetPanelRole()
		if err != nil {
			a.result(c, nil, err)
			c.Abort()
			return
		}
		if role != service.PanelRoleMaster {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "msg": "access_log_query_requires_master"})
			return
		}
		c.Next()
	})
	g.GET("", a.list)
	g.GET("/nodes", a.nodes)
	return a
}

func (a *AccessLogController) result(c *gin.Context, obj any, err error) {
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "obj": obj})
		return
	}
	status, code := http.StatusInternalServerError, "access_log_query_failed"
	if errors.Is(err, service.ErrInvalidAccessLogQuery) {
		status, code = http.StatusBadRequest, "invalid_access_log_query"
	}
	c.JSON(status, gin.H{"success": false, "msg": code})
}

func (a *AccessLogController) list(c *gin.Context) {
	var q service.AccessLogQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		a.result(c, nil, service.ErrInvalidAccessLogQuery)
		return
	}
	page, err := a.logs.Query(c.Request.Context(), q, time.Now())
	a.result(c, page, err)
}

func (a *AccessLogController) nodes(c *gin.Context) {
	options, err := a.logs.QueryNodes(c.Request.Context(), time.Now())
	a.result(c, options, err)
}
