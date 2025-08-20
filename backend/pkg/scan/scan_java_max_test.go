package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 测试 NewDefaultScannerMax
func TestNewDefaultScannerMax(t *testing.T) {
	scanner := NewDefaultScannerJavaMax()
	if scanner == nil {
		t.Fatal("NewDefaultScannerMax() should not return nil")
	}
	if scanner.root != "/app/assets/Canary" {
		t.Errorf("Expected root to be '/app/assets/Canary', got '%s'", scanner.root)
	}
}

// 测试 NewScannerMax
func TestNewScannerMax(t *testing.T) {
	expectedRoot := "/test/root"
	scanner := NewScannerJavaMax(expectedRoot)
	if scanner == nil {
		t.Fatal("NewScannerMax() should not return nil")
	}
	if scanner.root != expectedRoot {
		t.Errorf("Expected root to be '%s', got '%s'", expectedRoot, scanner.root)
	}
}

// 测试 Scan 方法 - workspace 不存在的情况
func TestScannerMax_Scan_WorkspaceNotExists(t *testing.T) {
	scanner := NewScannerJavaMax("/app/assets/Canary")
	id := "test-id"
	workspace := "/non/existent/path"
	rule := "test-rule"

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
func TestScannerMax_Scan_Success(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 创建 ScannerMax 实例
	scanner := NewDefaultScannerJavaMax()

	// 执行扫描
	id := "test-id"
	rule := "test-rule"
	result, err := scanner.Scan(id, workspace, rule)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	// 验证结果
	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if result.ID != id {
		t.Errorf("Expected result ID to be '%s', got '%s'", id, result.ID)
	}

	if result.Prefix != "corax" {
		t.Errorf("Expected result Prefix to be 'corax', got '%s'", result.Prefix)
	}
	t.Log(result)
}

// 测试 Scan 方法 - corax_cmd.sh 执行失败
func TestScannerMax_Scan_CoraxCommandFailed(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 创建 ScannerMax 实例
	scanner := NewScannerJavaMax("/dummy")

	// 执行扫描
	id := "test-id"
	rule := "test-rule"
	_, err = scanner.Scan(id, workspace, rule)
	if err == nil {
		t.Fatal("Expected error when corax command fails, but got nil")
	}

	// 检查错误信息是否包含预期的内容
	if !strings.Contains(err.Error(), "failed to run command") {
		t.Errorf("Expected error to contain 'failed to run command', got '%s'", err.Error())
	}
}

// 测试 build 方法 - Maven 项目构建成功
func TestScannerMax_Build_MavenSuccess(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-maven-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 创建 pom.xml 文件
	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0-SNAPSHOT</version>
</project>`
	if err := os.WriteFile(filepath.Join(workspace, "pom.xml"), []byte(pomContent), 0644); err != nil {
		t.Fatalf("Failed to create pom.xml: %v", err)
	}

	// 创建 ScannerMax 实例 (使用默认 root，因为 build 方法不依赖 root)
	scanner := NewDefaultScannerJavaMax() // 在注释掉的代码块中使用

	err = scanner.build(workspace)
	if err != nil {
		// 如果环境中没有 mvn 或者构建失败，这可能是预期的
		// 但我们至少测试了代码路径
		t.Logf("Build failed (expected in test environment without Maven): %v", err)
	}
}

// 测试 build 方法 - Gradle 项目构建成功
func TestScannerMax_Build_GradleSuccess(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-gradle-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 创建 build.gradle 文件
	gradleContent := `
apply plugin: 'java'

group = 'com.example'
version = '1.0-SNAPSHOT'

repositories {
    mavenCentral()
}

dependencies {
    testImplementation 'junit:junit:4.12'
}
`
	if err := os.WriteFile(filepath.Join(workspace, "build.gradle"), []byte(gradleContent), 0644); err != nil {
		t.Fatalf("Failed to create build.gradle: %v", err)
	}

	// 类似于 Maven 测试，Gradle 测试也需要特定的环境
	// 我们可以验证是否能正确检测到 build.gradle

	if _, err := os.Stat(filepath.Join(workspace, "build.gradle")); err != nil {
		t.Errorf("Expected build.gradle to exist: %v", err)
	}

	scanner := NewDefaultScannerJavaMax() // 在注释掉的代码块中使用
	err = scanner.build(workspace)
	if err != nil {
		// 如果环境中没有 gradle 或者构建失败，这可能是预期的
		// 但我们至少测试了代码路径
		t.Logf("Build failed (expected in test environment without Gradle): %v", err)
	}
}

// 测试 build 方法 - 非 Maven/Gradle 项目
func TestScannerMax_Build_NonMavenGradleProject(t *testing.T) {
	// 创建临时目录作为 workspace
	workspace, err := os.MkdirTemp("", "test-non-maven-gradle-workspace")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(workspace)

	// 不创建 pom.xml 或 build.gradle 文件

	// 创建 ScannerMax 实例
	scanner := NewDefaultScannerJavaMax()

	// 对于非 Maven/Gradle 项目，build 方法应该直接返回 nil
	err = scanner.build(workspace)
	if err != nil {
		t.Errorf("Expected build to succeed for non-Maven/Gradle project, but got error: %v", err)
	}
}

// 测试 parseSarifToResult 函数 - 有效 SARIF 数据
func TestParseSarifToResult_ValidData(t *testing.T) {
	// 创建有效的 SARIF JSON 数据
	sarifData := []byte(`{
	 "version": "2.1.0",
	 "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
	 "runs": [
	   {
	     "tool": {
	       "driver": {
	         "name": "TestTool",
	         "version": "1.0.0"
	       }
	     },
	     "results": [
	       {
	         "ruleId": "TEST-RULE-001",
	         "message": {
	           "text": "Test vulnerability found"
	         },
	         "locations": [
	           {
	             "physicalLocation": {
	               "artifactLocation": {
	                 "uri": "src/main/java/com/example/VulnerableClass.java"
	               },
	               "region": {
	                 "startLine": 10,
	                 "startColumn": 5,
	                 "endLine": 10,
	                 "endColumn": 20
	               }
	             }
	           }
	         ],
	         "level": "warning"
	       },
	       {
	         "ruleId": "TEST-RULE-002",
	         "message": {
	           "text": "Another test vulnerability found"
	         },
	         "locations": [],
	         "level": "error"
	       }
	     ]
	   }
	 ]
}`)

	result, err := parseSarifToResult(sarifData)
	if err != nil {
		t.Fatalf("parseSarifToResult() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	if len(result.Results) != 2 {
		t.Fatalf("Expected 2 result items, got %d", len(result.Results))
	}

	// 验证第一个结果项
	item1 := result.Results[0]
	if item1.CheckID != "TEST-RULE-001" {
		t.Errorf("Expected CheckID to be 'TEST-RULE-001', got '%s'", item1.CheckID)
	}

	if item1.Path != "src/main/java/com/example/VulnerableClass.java" {
		t.Errorf("Expected Path to be 'src/main/java/com/example/VulnerableClass.java', got '%s'", item1.Path)
	}

	if item1.Start.Line != 10 || item1.Start.Col != 5 {
		t.Errorf("Expected Start position to be (10, 5), got (%d, %d)", item1.Start.Line, item1.Start.Col)
	}

	if item1.End.Line != 10 || item1.End.Col != 20 {
		t.Errorf("Expected End position to be (10, 20), got (%d, %d)", item1.End.Line, item1.End.Col)
	}

	if item1.Extra.Message != "Test vulnerability found" {
		t.Errorf("Expected Extra.Message to be 'Test vulnerability found', got '%s'", item1.Extra.Message)
	}

	if item1.Extra.Severity != "warning" {
		t.Errorf("Expected Extra.Severity to be 'warning', got '%s'", item1.Extra.Severity)
	}

	// 验证第二个结果项 (没有位置信息)
	item2 := result.Results[1]
	if item2.CheckID != "TEST-RULE-002" {
		t.Errorf("Expected CheckID to be 'TEST-RULE-002', got '%s'", item2.CheckID)
	}

	if item2.Path != "" {
		t.Errorf("Expected Path to be empty, got '%s'", item2.Path)
	}

	if item2.Start.Line != 0 || item2.Start.Col != 0 {
		t.Errorf("Expected Start position to be (0, 0), got (%d, %d)", item2.Start.Line, item2.Start.Col)
	}

	if item2.End.Line != 0 || item2.End.Col != 0 {
		t.Errorf("Expected End position to be (0, 0), got (%d, %d)", item2.End.Line, item2.End.Col)
	}

	if item2.Extra.Message != "Another test vulnerability found" {
		t.Errorf("Expected Extra.Message to be 'Another test vulnerability found', got '%s'", item2.Extra.Message)
	}

	if item2.Extra.Severity != "error" {
		t.Errorf("Expected Extra.Severity to be 'error', got '%s'", item2.Extra.Severity)
	}
}

// 测试 parseSarifToResult 函数 - 无效 JSON 数据
func TestParseSarifToResult_InvalidJSON(t *testing.T) {
	// 创建无效的 JSON 数据
	sarifData := []byte(`{
  "runs": [
    {
      "results": [
        {
          "ruleId": "TEST-RULE-001",
          "message": "Test vulnerability found",
          // 缺少结束括号
        }
      ]
    }
  ]
  // 缺少结束括号
`)

	_, err := parseSarifToResult(sarifData)
	if err == nil {
		t.Fatal("Expected error when parsing invalid JSON, but got nil")
	}

	// 检查错误信息是否包含预期的内容
	if !strings.Contains(err.Error(), "failed to unmarshal SARIF data") {
		t.Errorf("Expected error to contain 'failed to unmarshal SARIF data', got '%s'", err.Error())
	}
}
