package scan

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

type ScannerJavaMax struct {
	root string
}

func NewDefaultScannerJavaMax() *ScannerJavaMax {
	return NewScannerJavaMax("/app/assets/Canary")
}

func NewScannerJavaMax(root string) *ScannerJavaMax {
	return &ScannerJavaMax{root: root}
}

func (s ScannerJavaMax) Scan(id string, workspace, rule string) (*Result, error) {
	if _, err := os.Stat(workspace); err != nil {
		return nil, fmt.Errorf("failed to stat workspace: %w", err)
	}

	// 构建工程
	if err := s.build(workspace); err != nil {
		// slog.Warn("[Scan] Failed to build project", "error", err)
		return nil, fmt.Errorf("failed to build project: %w", err)
	}

	//生成一个随机的临时目录
	tempDir, err := os.MkdirTemp("", "corax")
	if err != nil {
		// slog.Warn("[Scan] Failed to create temp directory", "error", err)
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 构建命令
	cmd := exec.Command(
		"sh",
		fmt.Sprintf("%s/corax_cmd.sh", s.root), //脚本路径
		s.root,                                 //corax的根目录
		workspace,                              //扫描工程路径
		tempDir,                                //输出临时目录路径
	)

	log.Printf("[Scan] Executing command: %s %s", cmd.Path, strings.Join(cmd.Args[1:], " "))
	// slog.Debug("[Scan] Executing command", "command", cmd.Path, "args", strings.Join(cmd.Args[1:], " "))

	// 执行命令
	out, err := cmd.CombinedOutput()
	if err != nil {
		// slog.Warn("[Scan] Failed to run command", "error", err)
		return nil, fmt.Errorf("failed to run command: %w", err)
	}

	// 从 /sarif 目录读取所有 .sarif 文件并解析
	result, err := parseSarifFilesToResult(fmt.Sprintf("%s/sarif", tempDir))
	if err != nil {
		// slog.Warn("[Scan] Failed to parse SARIF files", "error", err)
		return nil, fmt.Errorf("failed to parse SARIF files: %w", err)
	}

	// 设置 Result 的其他字段
	result.ID = id
	result.Output = string(out)
	result.Prefix = "corax"

	return result, nil
}

// parseSarifToResult 将单个 SARIF 文件的数据转换为 Result 结构
func parseSarifToResult(sarifData []byte) (*Result, error) {
	// 使用 SARIF 库解析数据
	sarifReport, err := sarif.FromBytes(sarifData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SARIF data: %w", err)
	}

	// 创建一个基本的 Result 结构
	result := &Result{
		Results: make([]*ResultItem, 0),
	}

	// 遍历 SARIF 报告中的所有运行
	for _, run := range sarifReport.Runs {
		messageMap := make(map[string]string)

		for _, rule := range run.Tool.Driver.Rules {
			s := *rule.MessageStrings
			messageMap[rule.ID] = *s["default"].Text
		}

		// 遍历每次运行中的所有结果
		for _, sarifResult := range run.Results {
			// 创建 ResultItem
			message := messageMap[getStringValue(sarifResult.RuleID)]
			resultItem := &ResultItem{
				CheckID: getStringValue(sarifResult.RuleID),
				Extra: Extra{
					Message:  message,
					Severity: "WARNING", //TODO目前从引擎结果无法直接获取严重程度，先统一填充为中等
					// 其他字段暂时留空，可以根据 SARIF 格式的扩展来填充
					Metadata: Metadata{
						MessageZh: message,
						AbstractFeysh: map[string]string{
							"en-US": message,
							"zh-CN": message,
						},
					},
				},
			}

			// 如果有位置信息，填充路径和位置
			if len(sarifResult.Locations) > 0 {
				location := sarifResult.Locations[0]
				if location.PhysicalLocation != nil &&
					location.PhysicalLocation.ArtifactLocation != nil &&
					location.PhysicalLocation.ArtifactLocation.URI != nil {
					resultItem.Path = strings.TrimPrefix(*location.PhysicalLocation.ArtifactLocation.URI, "file://")
				}

				if location.PhysicalLocation != nil &&
					location.PhysicalLocation.Region != nil {
					region := location.PhysicalLocation.Region
					resultItem.Start.Line = getIntValue(region.StartLine)
					resultItem.Start.Col = getIntValue(region.StartColumn)
					if region.EndLine == nil {
						resultItem.End.Line = resultItem.Start.Line
					} else {
						resultItem.End.Line = getIntValue(region.EndLine)
					}

					resultItem.End.Col = getIntValue(region.EndColumn)
				}
			}

			// 添加到结果集中
			result.Results = append(result.Results, resultItem)
		}
	}

	return result, nil
}

// getStringValue 安全地从 *string 获取字符串值
func getStringValue(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// getIntValue 安全地从 *int 获取整数值
func getIntValue(i *int) int {
	if i != nil {
		return *i
	}
	return 0
}

// getMessageText 从 SARIF Message 结构中提取文本
func getMessageText(message *sarif.Message) string {
	if message != nil && message.Text != nil {
		return *message.Text
	}
	return ""
}

// parseSarifFilesToResult 从指定目录读取所有 .sarif 文件并解析为一个 Result 结构
func parseSarifFilesToResult(dir string) (*Result, error) {
	// 创建一个基本的 Result 结构
	result := &Result{
		Results: make([]*ResultItem, 0),
	}

	// 遍历目录下的所有 .sarif 文件
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 检查是否为 .sarif 文件
		if !info.IsDir() && filepath.Ext(path) == ".sarif" {
			// 读取文件内容
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read SARIF file %s: %w", path, err)
			}

			// 解析 SARIF 数据
			sarifResult, err := parseSarifToResult(b)
			if err != nil {
				return fmt.Errorf("failed to parse SARIF file %s: %w", path, err)
			}

			// 将解析结果合并到主结果中
			result.Results = append(result.Results, sarifResult.Results...)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk SARIF directory: %w", err)
	}

	return result, nil
}

// build 根据工程类型构建项目
func (s ScannerJavaMax) build(workspace string) error {
	// 检查是否为 Maven 项目
	if _, err := os.Stat(fmt.Sprintf("%s/pom.xml", workspace)); err == nil {
		return s.buildMaven(workspace)
	}

	// 检查是否为 Gradle 项目
	if _, err := os.Stat(fmt.Sprintf("%s/build.gradle", workspace)); err == nil {
		return s.buildGradle(workspace)
	}

	// 检查是否为 Gradle Kotlin 项目
	if _, err := os.Stat(fmt.Sprintf("%s/build.gradle.kts", workspace)); err == nil {
		return s.buildGradle(workspace)
	}

	// 如果不是 Maven 或 Gradle 项目，直接返回
	return nil
}

// buildMaven 构建 Maven 项目
func (s ScannerJavaMax) buildMaven(workspace string) error {
	cmd := exec.Command("mvn", "package", "-Dmaven.test.skip.exec=true")
	cmd.Dir = workspace

	// slog.Debug("[Build] Executing Maven command", "command", cmd.Path, "args", strings.Join(cmd.Args[1:], " "), "directory", workspace)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build Maven project: %w out: %s", err, string(out))
	}

	// slog.Debug("[Build] Maven build successful", "output", string(out))
	return nil
}

// buildGradle 构建 Gradle 项目
func (s ScannerJavaMax) buildGradle(workspace string) error {
	cmd := exec.Command("gradle", "build", "-x", "test")
	cmd.Dir = workspace

	// slog.Debug("[Build] Executing Gradle command", "command", cmd.Path, "args", strings.Join(cmd.Args[1:], " "), "directory", workspace)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to build Gradle project: %w out: %s", err, string(out))
	}

	// slog.Debug("[Build] Gradle build successful", "output", string(out))
	return nil
}
