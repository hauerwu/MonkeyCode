package scan

import (
	"fmt"
)

// ScannerChain 实现了Scanner接口，支持按顺序调用多个Scanner
type ScannerChain struct {
	scanners []Scanner
}

// NewScannerChain 创建一个新的ScannerChain实例
func NewScannerChain(scanners ...Scanner) *ScannerChain {
	return &ScannerChain{
		scanners: scanners,
	}
}

// Scan 按顺序调用扫描器，成功就退出，失败再调用下一个Scanner
func (sc *ScannerChain) Scan(id string, workspace, rule string) (*Result, error) {
	var lastErr error

	for _, scanner := range sc.scanners {
		result, err := scanner.Scan(id, workspace, rule)
		if err == nil {
			// 扫描成功，直接返回结果
			return result, nil
		}
		// 记录最后一个错误，继续尝试下一个扫描器
		lastErr = err
	}

	// 所有扫描器都失败了，返回最后一个错误
	if lastErr != nil {
		return nil, fmt.Errorf("all scanners failed: %w", lastErr)
	}

	// 这种情况理论上不会发生，但为了安全起见还是处理一下
	return nil, fmt.Errorf("all scanners failed with no specific error")
}
