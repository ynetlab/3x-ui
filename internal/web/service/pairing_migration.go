package service

import (
	"context"
	"encoding/json"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/mhsanaei/3x-ui/v3/internal/cluster"
	"github.com/mhsanaei/3x-ui/v3/internal/crypto/nodetoken"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// Only configuration enters the snapshot; heartbeat samples must not invalidate
// an enrollment. Stored credentials are hashed with the other fields, not copied.
func migrationSnapshot(n *model.Node) string {
	data, _ := json.Marshal([]any{
		n.Id, n.Name, n.Remark, n.Guid, n.Scheme, n.Address, n.Port, n.BasePath,
		n.ApiToken, n.Enable, n.AllowPrivateAddress, n.TlsVerifyMode, n.PinnedCertSha256,
		n.InboundSyncMode, n.InboundTags, n.OutboundTag, n.ControlConnection, n.ControlRecoveryRequired, n.ControlRecoveryEnable,
	})
	return pairingHash(string(data))
}

func migrationNode(ctx context.Context, id int) (*model.Node, error) {
	var node model.Node
	if id < 1 {
		return nil, pairingError(404, "migration_node_not_found")
	}
	if err := pairingDB().WithContext(ctx).First(&node, id).Error; err != nil {
		if database.IsNotFound(err) {
			return nil, pairingError(404, "migration_node_not_found")
		}
		return nil, err
	}
	if node.ControlConnection {
		return nil, pairingError(409, "migration_node_already_paired")
	}
	if !validPairingID(node.Guid) {
		return nil, pairingError(409, "migration_node_identity_required")
	}
	var count int64
	if err := pairingDB().Model(&model.Node{}).Where("guid = ?", node.Guid).Count(&count).Error; err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, pairingError(409, "migration_node_identity_mismatch")
	}
	ctx, cancel := context.WithTimeout(ctx, cluster.PairingRequestTimeout)
	defer cancel()
	proof, err := (&NodeService{}).Probe(ctx, &node)
	if err != nil || proof.Guid != node.Guid {
		return nil, pairingError(409, "migration_node_verification_failed")
	}
	return &node, nil
}

func checkMigrationNode(tx *gorm.DB, row *model.NodeEnrollment) (*model.Node, error) {
	var node model.Node
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&node, row.ExistingNodeID).Error; err != nil {
		if database.IsNotFound(err) {
			return nil, pairingError(410, "migration_node_not_found")
		}
		return nil, err
	}
	if (node.ControlConnection && (!row.Recovery || !node.ControlRecoveryRequired)) || node.Guid != row.ExpectedGUID || migrationSnapshot(&node) != row.MigrationSnapshot {
		return nil, pairingError(409, "migration_node_changed")
	}
	return &node, nil
}

func commitMigrationNode(tx *gorm.DB, row *model.NodeEnrollment, replacement *model.Node) error {
	old, err := checkMigrationNode(tx, row)
	if err != nil {
		return err
	}
	token, err := nodetoken.Encrypt(old.Id, replacement.ApiToken)
	if err != nil {
		return err
	}
	replacement.Id = old.Id
	// Preserve all identity, attribution, selection and usage rows. In particular,
	// do not call createTx or MarkNodeDirty: migration must not redeploy inbounds.
	return tx.Model(old).Updates(map[string]any{
		"scheme": replacement.Scheme, "address": replacement.Address, "port": replacement.Port,
		"base_path": replacement.BasePath, "api_token": token, "tls_verify_mode": replacement.TlsVerifyMode,
		"pinned_cert_sha256": replacement.PinnedCertSha256, "control_connection": true,
		"allow_private_address": replacement.AllowPrivateAddress,
	}).Error
}

// Migration keeps the old panel certificate until registration is ready to
// commit. A failed callback/DB commit rolls back; a crash uses the normal lease.
func activateMigrationCertificate(ctx context.Context, row *model.NodeEnrollment, s *NodeCertificateService) (func(), error) {
	if row.ExistingNodeID == 0 {
		return nil, nil
	}
	if _, err := checkMigrationNode(pairingDB(), row); err != nil {
		return nil, err
	}
	var job model.NodeCertificateJob
	if err := pairingDB().Where("enrollment_id = ? AND node_id = 0 AND status = ?", row.ID, "staged").First(&job).Error; err != nil {
		return nil, pairingError(503, "migration_certificate_pending")
	}
	if s == nil {
		s = &NodeCertificateService{}
	}
	bundle, err := openCertificateBundle(&job)
	if err != nil {
		return nil, err
	}
	target, err := s.enrollmentTarget(ctx, &job)
	if err != nil {
		return nil, err
	}
	rollback := func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), cluster.PairingRequestTimeout)
		defer cancel()
		_ = pairingRPC(rollbackCtx, target.tls, target.allowPrivate, pairingURL(target.address, target.port, "/cluster/v1/certificates/rollback"), target.token,
			CertificateInstallRequest{ID: job.ID, EnrollmentID: row.ID}, &CertificateInstallReceipt{})
	}
	if err := s.deployBundle(ctx, &job, bundle); err != nil {
		rollback()
		return nil, err
	}
	return rollback, nil
}

func stageMigrationCertificate(ctx context.Context, job *model.NodeCertificateJob) (bool, error) {
	if job.NodeID != 0 || job.EnrollmentID == "" {
		return false, nil
	}
	row, err := (&PairingService{}).enrollment(job.EnrollmentID)
	if err != nil || row.ExistingNodeID == 0 {
		return false, err
	}
	target, err := (&NodeCertificateService{}).enrollmentTarget(ctx, job)
	if err != nil {
		return true, err
	}
	bundle, err := openCertificateBundle(job)
	if err != nil {
		return true, err
	}
	var receipt CertificateInstallReceipt
	err = pairingRPC(ctx, target.tls, target.allowPrivate, pairingURL(target.address, target.port, "/cluster/v1/certificates/stage"), target.token,
		CertificateInstallRequest{ID: job.ID, EnrollmentID: row.ID, Bundle: &bundle}, &receipt)
	if err != nil {
		return true, err
	}
	if receipt.ID != job.ID || receipt.Fingerprint != job.Fingerprint || receipt.Phase != "staged" {
		return true, pairingError(502, "invalid_certificate_receipt")
	}
	return true, pairingDB().Model(job).Updates(map[string]any{"status": "staged", "last_error": "", "next_attempt_at": time.Now().Add(30 * time.Second).UnixMilli()}).Error
}
