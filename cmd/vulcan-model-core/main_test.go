package main

import "testing"

// TestParseRunOptionsUsesLocalControlPlaneDefaults verifies the core never defaults to a publicly reachable random listener.
// TestParseRunOptionsUsesLocalControlPlaneDefaults 验证核心绝不默认使用可公开访问的随机监听器。
func TestParseRunOptionsUsesLocalControlPlaneDefaults(t *testing.T) {
	// options records startup defaults without creating database, secret, or network side effects.
	// options 记录启动默认值而不创建数据库、Secret 或网络副作用。
	options, errOptions := parseRunOptions(nil)
	if errOptions != nil {
		t.Fatalf("parse default run options: %v", errOptions)
	}
	if options.listenAddress != "127.0.0.1:13514" {
		t.Fatalf("default listen address = %q, want %q", options.listenAddress, "127.0.0.1:13514")
	}
	if options.databasePath != defaultDatabasePath || options.configurationPath == "" || options.secretDirectory != defaultSecretDirectory {
		t.Fatalf("unexpected default options: %+v", options)
	}
}

// TestParseRunOptionsAcceptsExplicitLocalOverrides verifies operators can choose test-local paths and listeners deliberately.
// TestParseRunOptionsAcceptsExplicitLocalOverrides 验证操作员可以有意选择测试本地路径和监听器。
func TestParseRunOptionsAcceptsExplicitLocalOverrides(t *testing.T) {
	// args supplies an explicit complete override set.
	// args 提供一组完整的显式覆盖值。
	args := []string{"--listen-address", "127.0.0.1:14514", "--database-path", "test.db", "--config", "test.yaml", "--secret-directory", "test.secrets"}
	options, errOptions := parseRunOptions(args)
	if errOptions != nil {
		t.Fatalf("parse explicit run options: %v", errOptions)
	}
	if options.listenAddress != "127.0.0.1:14514" || options.databasePath != "test.db" || options.configurationPath != "test.yaml" || options.secretDirectory != "test.secrets" {
		t.Fatalf("explicit options = %+v", options)
	}
}
