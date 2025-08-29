package scan

import (
	"errors"
	"testing"
)

// MockScannerForChain 是一个用于ScannerChain测试的模拟Scanner实现
type MockScannerForChain struct {
	shouldFail bool
	result     *Result
	err        error
}

func (m *MockScannerForChain) Scan(id string, workspace, rule string) (*Result, error) {
	if m.shouldFail {
		return nil, m.err
	}
	return m.result, nil
}

func TestScannerChain_Scan_Success(t *testing.T) {
	// 创建一个成功的扫描器
	successResult := &Result{ID: "test-id", Output: "test-output"}
	successScanner := &MockScannerForChain{
		shouldFail: false,
		result:     successResult,
	}

	// 创建ScannerChain
	chain := NewScannerChain(successScanner)

	// 执行扫描
	result, err := chain.Scan("test-id", "/test/workspace", "/test/rule")

	// 验证结果
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if result != successResult {
		t.Errorf("Expected result to be %v, got %v", successResult, result)
	}
}

func TestScannerChain_Scan_FailureThenSuccess(t *testing.T) {

	// 创建ScannerChain
	chain := NewScannerChain(NewScannerLite(), NewScannerLite())

	workspace := "/root/code/sast_test/java-gradle-demo"
	// 执行扫描
	result, err := chain.Scan("test-id", workspace, "java")

	// 验证结果
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	t.Log(result)
}

func TestScannerChain_Scan_AllFailures(t *testing.T) {
	// 创建两个失败的扫描器
	failureScanner1 := &MockScannerForChain{
		shouldFail: true,
		err:        errors.New("first scanner failed"),
	}
	failureScanner2 := &MockScannerForChain{
		shouldFail: true,
		err:        errors.New("second scanner failed"),
	}

	// 创建ScannerChain
	chain := NewScannerChain(failureScanner1, failureScanner2)

	// 执行扫描
	result, err := chain.Scan("test-id", "/test/workspace", "/test/rule")

	// 验证结果
	if err == nil {
		t.Error("Expected an error, got none")
	}
	if result != nil {
		t.Errorf("Expected result to be nil, got %v", result)
	}
	// 检查错误信息是否包含最后一个错误
	expectedErrMsg := "all scanners failed: second scanner failed"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message to be '%s', got '%s'", expectedErrMsg, err.Error())
	}
}
