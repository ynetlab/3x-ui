package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

type PairingController struct{ pairing service.PairingService }

func NewPairingController(g *gin.RouterGroup) *PairingController {
	c := &PairingController{}
	p := g.Group("/pairings")
	p.GET("/control", c.control)
	p.POST("/enrollments", c.create)
	p.GET("/enrollments/:id", c.enrollment)
	p.POST("/joins", c.join)
	p.GET("/joins/:id", c.status)
	p.POST("/joins/:id/resume", c.resume)
	return c
}

func (p *PairingController) control(c *gin.Context) {
	value, err := p.pairing.ControlInfo()
	pairingResult(c, value, err)
}

func pairingResult(c *gin.Context, value any, err error) {
	c.Header("Cache-Control", "no-store")
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "obj": value})
		return
	}
	status, code := http.StatusInternalServerError, "pairing_storage_error"
	var pe *service.PairingError
	if errors.As(err, &pe) {
		status, code = pe.Status, pe.Code
	} else if database.IsNotFound(err) {
		status, code = http.StatusNotFound, "pairing_not_found"
	}
	c.JSON(status, gin.H{"success": false, "msg": code})
}

func (p *PairingController) create(c *gin.Context) {
	var req service.CreateEnrollmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pairingResult(c, nil, &service.PairingError{Status: 400, Code: "invalid_pairing_request"})
		return
	}
	value, err := p.pairing.CreateEnrollment(req)
	pairingResult(c, value, err)
}
func (p *PairingController) enrollment(c *gin.Context) {
	value, err := p.pairing.EnrollmentStatus(c.Param("id"))
	pairingResult(c, value, err)
}
func (p *PairingController) join(c *gin.Context) {
	var req service.JoinPairingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pairingResult(c, nil, &service.PairingError{Status: 400, Code: "invalid_pairing_request"})
		return
	}
	value, err := p.pairing.StartJoin(req)
	pairingResult(c, value, err)
}
func (p *PairingController) status(c *gin.Context) {
	value, err := p.pairing.JoinStatus(c.Param("id"))
	pairingResult(c, value, err)
}
func (p *PairingController) resume(c *gin.Context) {
	value, err := p.pairing.ResumeJoin(c.Param("id"))
	pairingResult(c, value, err)
}
