package scan

import (
	"testing"

	"github.com/chaitin/MonkeyCode/backend/consts"
)

// MockScanner 是一个模拟的 Scanner 实现，用于测试
type MockScanner struct {
	scanFunc func(id string, workspace, rule string) (*Result, error)
}

func (m *MockScanner) Scan(id string, workspace, rule string) (*Result, error) {
	if m.scanFunc != nil {
		return m.scanFunc(id, workspace, rule)
	}
	return nil, nil
}

func TestNewScannerMgr(t *testing.T) {
	mgr := NewScannerMgr()
	if mgr == nil {
		t.Fatal("NewScannerMgr() should not return nil")
	}
	if mgr.scannerMap == nil {
		t.Error("scannerMap should be initialized")
	}
}

func TestScannerMgr_RegisterScanner(t *testing.T) {
	mgr := NewScannerMgr()
	mockScanner := &MockScanner{}

	// 注册一个扫描器
	mgr.RegisterScanner(consts.SecurityScanningLanguageJava, consts.SecurityScanningModeMax, mockScanner)

	// 验证扫描器是否正确注册
	if mgr.scannerMap[consts.SecurityScanningLanguageJava] == nil {
		t.Error("Language map should be created")
	}
	if mgr.scannerMap[consts.SecurityScanningLanguageJava][consts.SecurityScanningModeMax] != mockScanner {
		t.Error("Scanner should be registered correctly")
	}
}

func TestScannerMgr_GetScanner(t *testing.T) {
	mgr := NewScannerMgr()
	mockScannerMax := &MockScanner{}
	mockScannerLite := &MockScanner{}

	// 注册两个扫描器
	mgr.RegisterScanner(consts.SecurityScanningLanguageJava, consts.SecurityScanningModeMax, mockScannerMax)
	mgr.RegisterScanner(consts.SecurityScanningLanguageJava, consts.SecurityScanningModeLite, mockScannerLite)

	// 测试获取已注册的扫描器
	scanner := mgr.GetScanner(consts.SecurityScanningLanguageJava, consts.SecurityScanningModeMax)
	if scanner != mockScannerMax {
		t.Error("Should return the registered max scanner")
	}

	// 测试获取不存在语言的扫描器
	scanner = mgr.GetScanner(consts.SecurityScanningLanguageGo, consts.SecurityScanningModeMax)
	if scanner != nil {
		t.Error("Should return nil for non-existent language")
	}

	// 测试获取不存在模式的扫描器
	// 使用一个不存在的模式来测试
	nonExistentMode := consts.SecurityScanningMode("standard")
	scanner = mgr.GetScanner(consts.SecurityScanningLanguageJava, nonExistentMode)
	if scanner != nil {
		t.Error("Should return nil for non-existent mode")
	}

	// 测试获取 max 模式但未注册时回退到 lite 模式
	mgr2 := NewScannerMgr()
	mgr2.RegisterScanner(consts.SecurityScanningLanguageJava, consts.SecurityScanningModeLite, mockScannerLite)
	scanner = mgr2.GetScanner(consts.SecurityScanningLanguageJava, consts.SecurityScanningModeMax)
	if scanner != mockScannerLite {
		t.Error("Should fallback to lite mode when max mode is not available")
	}
}
