package main

import (
	"context"
	"errors"
	"log/slog"
	"os/signal"
	"syscall"

	"gorm.io/gorm"

	"github.com/karlo/authentication-service/internal/archive"
	"github.com/karlo/authentication-service/internal/config"
	"github.com/karlo/authentication-service/internal/platform/coldstore"
)

func runArchive(cfg *config.Config, db *gorm.DB, dryRun bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := coldstore.NewS3(ctx, cfg.ArchiveBucket, cfg.ArchiveRegion)
	if err != nil {
		return err
	}
	if !store.Configured() {
		return errors.New("archive: ARCHIVE_BUCKET is not set; nowhere to write")
	}

	sum, err := archive.New(db, store, archive.Options{
		AuditRetain:   cfg.ArchiveAuditRetain,
		SessionRetain: cfg.ArchiveSessionRetain,
		Batch:         cfg.ArchiveBatch,
		KeepAuditRows: cfg.ArchiveKeepAuditRows,
		DryRun:        dryRun,
		Prefix:        cfg.ArchivePrefix,
	}).Run(ctx)
	slog.Info("archive run finished", "auditRows", sum.AuditRows, "auditFiles", sum.AuditFiles,
		"bytes", sum.Bytes, "sessionsDeleted", sum.SessionsDeleted, "dryRun", dryRun)
	return err
}
