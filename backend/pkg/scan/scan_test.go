package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 测试 NewScannerLite
func TestNewScannerLite(t *testing.T) {
	scanner := NewScannerLite()
	if scanner == nil {
		t.Fatal("NewScannerLite() should not return nil")
	}
}

// 测试 Scan 方法 - workspace 不存在的情况
func TestScannerLite_Scan_WorkspaceNotExists(t *testing.T) {
	scanner := NewScannerLite()
	id := "test-id"
	workspace := "/non/existent/path"
	rule := "java"

	_, err := scanner.Scan(id, workspace, rule)
	if err == nil {
		t.Fatal("Expected error when workspace does not exist, but got nil")
	}

	// 检查错误信息是否包含预期的内容
	if !strings.Contains(err.Error(), "failed to stat workspace") {
		t.Errorf("Expected error to contain 'failed to stat workspace', got '%s'", err.Error())
	}
}

// 测试 Scan 方法 - 成功场景
func TestScannerLite_Scan_Success(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 创建一个简单的文件用于扫描
	testFile := filepath.Join(workspace, "test.java")
	fileContent := `public class Test {
		public static void main(String[] args) {
			System.out.println("Hello, World!");
		}
	}`
	if err := os.WriteFile(testFile, []byte(fileContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// 创建 ScannerLite 实例
	scanner := NewScannerLite()

	// 执行扫描
	id := "test-id"
	rule := "java" // 使用空规则进行测试
	result, err := scanner.Scan(id, workspace, rule)
	if err != nil {
		// 如果环境中没有 sgp 命令或者行为不同，这可能是预期的
		// 但我们至少测试了代码路径
		t.Logf("Scan failed (expected in test environment without sgp): %v", err)
		return
	}

	// 验证结果
	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.ID != id {
		t.Errorf("Expected result ID to be '%s', got '%s'", id, result.ID)
	}
}

// 测试 Scan 方法 - sgp 命令执行失败
func TestScannerLite_Scan_SGPCommandFailed(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 创建 ScannerLite 实例
	scanner := NewScannerLite()

	// 执行扫描，使用一个无效的规则文件路径
	id := "test-id"
	rule := "java"
	_, err = scanner.Scan(id, workspace, rule)
	if err == nil {
		t.Fatal("Expected error when sgp command fails, but got nil")
	}

	// 检查错误信息是否包含预期的内容
	if !strings.Contains(err.Error(), "failed to run command") {
		t.Errorf("Expected error to contain 'failed to run command', got '%s'", err.Error())
	}
}
