package v1

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/GoYoko/web"

	"github.com/chaitin/MonkeyCode/backend/consts"
	"github.com/chaitin/MonkeyCode/backend/domain"
	"github.com/chaitin/MonkeyCode/backend/pkg/scan"
)

type ScannerHandler struct {
	logger     *slog.Logger
	scannerMgr *scan.ScannerMgr
}

func NewScannerHandler(w *web.Web, logger *slog.Logger) *ScannerHandler {
	s := &ScannerHandler{
		logger:     logger,
		scannerMgr: scan.NewScannerMgr(),
	}

	liteScanner := scan.NewScannerLite()
	// 注册所有语言的Lite模式scanner
	for _, language := range []consts.SecurityScanningLanguage{
		consts.SecurityScanningLanguageCpp,
		consts.SecurityScanningLanguageJava,
		consts.SecurityScanningLanguagePython,
		consts.SecurityScanningLanguageJavaScript,
		consts.SecurityScanningLanguageGo,
		consts.SecurityScanningLanguagePHP,
		consts.SecurityScanningLanguageCS,
		consts.SecurityScanningLanguageSwift,
		consts.SecurityScanningLanguageRuby,
		consts.SecurityScanningLanguageRust,
		consts.SecurityScanningLanguageHTML,
		consts.SecurityScanningLanguageObjectiveC,
		consts.SecurityScanningLanguageOCaml,
		consts.SecurityScanningLanguageKotlin,
		consts.SecurityScanningLanguageScala,
		consts.SecurityScanningLanguageSolidity,
		consts.SecurityScanningLanguageCOBOL,
		consts.SecurityScanningLanguageShell,
		consts.SecurityScanningLanguageSQL,
		consts.SecurityScanningLanguageFortran,
		consts.SecurityScanningLanguageDart,
		consts.SecurityScanningLanguageGroovy,
		consts.SecurityScanningLanguageLua,
		consts.SecurityScanningLanguageSecrets,
		consts.SecurityScanningLanguageIaC,
	} {
		s.scannerMgr.RegisterScanner(language, consts.SecurityScanningModeLite, liteScanner)
	}

	// 暂时只有Java语言支持Max模式(max模式扫描失败退回lite模式扫描)
	s.scannerMgr.RegisterScanner(consts.SecurityScanningLanguageJava,
		consts.SecurityScanningModeMax,
		scan.NewScannerChain(scan.NewDefaultScannerJavaMax(), liteScanner))

	w.POST("/api/v1/scan", web.BindHandler(s.Scan))

	return s
}

func (s *ScannerHandler) Scan(ctx *web.Context, req domain.ScanReq) error {

	scanner := s.scannerMgr.GetScanner(req.Language, req.Mode)
	if scanner == nil {
		return fmt.Errorf("unknown scanner for language: %s and mode: %s", req.Language, req.Mode)
	}
	result, err := scanner.Scan(req.TaskID, req.Workspace, req.Language.Rule())
	if err != nil {
		s.logger.With("id", req.TaskID).With("error", err).ErrorContext(ctx.Request().Context(), "failed to scan")
		return fmt.Errorf("failed to scan: %w", err)
	}
	s.logger.With("id", req.TaskID).InfoContext(ctx.Request().Context(), "task done")
	return ctx.JSON(http.StatusOK, result)
}
