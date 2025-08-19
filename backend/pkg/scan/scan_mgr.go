package scan

import "github.com/chaitin/MonkeyCode/backend/consts"

type ScannerMgr struct {
	scannerMap map[consts.SecurityScanningLanguage]map[consts.SecurityScanningMode]Scanner
}

func NewScannerMgr() *ScannerMgr {
	return &ScannerMgr{
		scannerMap: make(map[consts.SecurityScanningLanguage]map[consts.SecurityScanningMode]Scanner),
	}
}

func (sm *ScannerMgr) RegisterScanner(language consts.SecurityScanningLanguage, mode consts.SecurityScanningMode, scanner Scanner) {
	if sm.scannerMap[language] == nil {
		sm.scannerMap[language] = make(map[consts.SecurityScanningMode]Scanner)
	}
	sm.scannerMap[language][mode] = scanner
}

func (sm *ScannerMgr) GetScanner(language consts.SecurityScanningLanguage, mode consts.SecurityScanningMode) Scanner {
	// 先根据语言和模式获取scanner
	if sm.scannerMap[language] == nil {
		return nil
	}

	scanner := sm.scannerMap[language][mode]

	// 如果是max模式且获取不到，则退回为lite模式
	if mode == consts.SecurityScanningModeMax && scanner == nil {
		scanner = sm.scannerMap[language][consts.SecurityScanningModeLite]
	}

	return scanner
}
