package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

func NewAccessAnalysisController(api *gin.RouterGroup) {
	result := &AccessLogController{}
	analytics := &service.AccessAnalysisService{}
	g := api.Group("/access-analysis")
	g.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		role, err := (&service.SettingService{}).GetPanelRole()
		if err != nil {
			result.result(c, nil, err)
			c.Abort()
			return
		}
		if role != service.PanelRoleMaster {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "msg": "access_log_query_requires_master"})
			return
		}
		c.Next()
	})
	g.GET("/overview", func(c *gin.Context) {
		var q service.AccessAnalysisQuery
		if err := c.ShouldBindQuery(&q); err != nil {
			result.result(c, nil, service.ErrInvalidAccessLogQuery)
			return
		}
		data, err := analytics.Overview(c.Request.Context(), q, time.Now())
		result.result(c, data, err)
	})
	g.GET("/stats", func(c *gin.Context) {
		var q service.AccessAnalysisQuery
		if err := c.ShouldBindQuery(&q); err != nil {
			result.result(c, nil, service.ErrInvalidAccessLogQuery)
			return
		}
		data, err := analytics.Page(c.Request.Context(), q, time.Now())
		result.result(c, data, err)
	})
	g.POST("/mmdb", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, (512<<20)+(1<<20))
		file, err := c.FormFile("file")
		if c.Request.MultipartForm != nil {
			defer func() { _ = c.Request.MultipartForm.RemoveAll() }()
		}
		if err != nil || file.Size > 512<<20 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid_access_city_database"})
			return
		}
		reader, err := file.Open()
		if err != nil {
			result.result(c, nil, err)
			return
		}
		defer reader.Close()
		if err = service.ImportAccessCityDatabase(reader); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "msg": "invalid_access_city_database"})
			return
		}
		result.result(c, nil, nil)
	})
}
