// Package main starts the minimal Vulcan Model Core process.
// main 包启动最小化的 Vulcan Model Core 进程。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/httpapi"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/refresh"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/secret"
	"github.com/OpenVulcan/vulcan-model-core/internal/sqlitestore"
)

const (
	// defaultListenAddress is the loopback-only default core API listener.
	// defaultListenAddress 是仅环回默认核心 API 监听地址。
	defaultListenAddress = "127.0.0.1:13514"
	// defaultDatabasePath is the conventional local SQLite state path.
	// defaultDatabasePath 是约定的本地 SQLite 状态路径。
	defaultDatabasePath = "vulcan-model-core.db"
	// defaultSecretDirectory is the conventional local OS-protected secret directory.
	// defaultSecretDirectory 是约定的本地操作系统保护 Secret 目录。
	defaultSecretDirectory = "vulcan-model-core.secrets"
)

// runOptions contains the complete process-local startup configuration after command-line parsing.
// runOptions 包含命令行解析后的完整进程本地启动配置。
type runOptions struct {
	// listenAddress is the exact local TCP address for the core HTTP API.
	// listenAddress 是核心 HTTP API 的精确本地 TCP 地址。
	listenAddress string
	// databasePath is the durable SQLite configuration and catalog location.
	// databasePath 是持久化 SQLite 配置和目录位置。
	databasePath string
	// configurationPath is the YAML control-plane configuration location.
	// configurationPath 是 YAML 控制面配置位置。
	configurationPath string
	// secretDirectory is the local directory for OS-protected provider credential files.
	// secretDirectory 是保存操作系统保护供应商凭据文件的本地目录。
	secretDirectory string
}

// main starts the process and reports terminal startup or shutdown failures.
// main 启动进程并报告最终的启动或关闭失败。
func main() {
	// ctx is cancelled by supported operating system termination signals.
	// ctx 在收到支持的操作系统终止信号时取消。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if errRun := run(ctx, os.Args[1:]); errRun != nil {
		log.Printf("vulcan-model-core stopped with error: %v", errRun)
		os.Exit(1)
	}
}

// parseRunOptions parses isolated startup flags without mutating global flag state.
// parseRunOptions 解析隔离的启动标志且不修改全局标志状态。
func parseRunOptions(args []string) (runOptions, error) {
	// flags owns command line parsing without global mutable flag state.
	// flags 独立管理命令行解析，避免使用全局可变标志状态。
	flags := flag.NewFlagSet("vulcan-model-core", flag.ContinueOnError)
	// options accumulates every validated process-local startup setting.
	// options 汇集每项经过验证的进程本地启动设置。
	options := runOptions{}
	flags.StringVar(&options.listenAddress, "listen-address", defaultListenAddress, "HTTP listen address")
	flags.StringVar(&options.databasePath, "database-path", defaultDatabasePath, "SQLite configuration and catalog path")
	flags.StringVar(&options.configurationPath, "config", runtimeconfig.DefaultPath, "Local control-plane YAML configuration path")
	flags.StringVar(&options.secretDirectory, "secret-directory", defaultSecretDirectory, "Local protected secret directory")
	if errParse := flags.Parse(args); errParse != nil {
		return runOptions{}, fmt.Errorf("parse command flags: %w", errParse)
	}
	return options, nil
}

// run parses configuration and serves the minimal HTTP API until cancellation.
// run 解析配置并提供最小 HTTP API，直到收到取消信号。
func run(ctx context.Context, args []string) error {
	// options contains all explicit or default local process settings.
	// options 包含全部显式或默认的本地进程设置。
	options, errOptions := parseRunOptions(args)
	if errOptions != nil {
		return errOptions
	}
	// Antigravity version refresh is decoupled from requests exactly as in CLIProxyAPI.
	// Antigravity 版本刷新与请求解耦，行为与 CLIProxyAPI 完全一致。
	providergoogle.StartAntigravityVersionUpdater(ctx)
	// controlConfiguration owns the hashed management key and plaintext call-plane API key lifecycle.
	// controlConfiguration 管理已散列的管理密钥和明文调用面 API 密钥生命周期。
	controlConfiguration, errControlConfiguration := runtimeconfig.Load(options.configurationPath)
	if errControlConfiguration != nil {
		return fmt.Errorf("load local control-plane configuration: %w", errControlConfiguration)
	}
	// secrets stores upstream provider credentials behind the operating-system protection boundary.
	// secrets 在操作系统保护边界后存储上游供应商凭据。
	secrets, errSecrets := secret.NewLocalStore(options.secretDirectory)
	if errSecrets != nil {
		return fmt.Errorf("create local protected secret store: %w", errSecrets)
	}

	// protocols owns shared upstream protocol metadata registered by future adapters.
	// protocols 管理由未来 Adapter 注册的共享上游协议元数据。
	protocols := providerconfig.NewProtocolRegistry()
	if errRegisterProtocols := bootstrap.RegisterProtocolProfiles(protocols); errRegisterProtocols != nil {
		return fmt.Errorf("register built-in protocol profiles: %w", errRegisterProtocols)
	}
	// systemDefinitions owns immutable code-registered provider definitions.
	// systemDefinitions 管理代码注册的不可变系统供应商定义。
	systemDefinitions, errSystemDefinitions := providerconfig.NewSystemRegistry(protocols)
	if errSystemDefinitions != nil {
		return fmt.Errorf("create system provider registry: %w", errSystemDefinitions)
	}
	if errRegisterProviders := bootstrap.RegisterSystemProviders(systemDefinitions); errRegisterProviders != nil {
		return fmt.Errorf("register built-in system providers: %w", errRegisterProviders)
	}
	// database owns durable non-secret configuration and atomic catalog snapshots.
	// database 管理持久化非秘密配置与原子目录快照。
	database, errDatabase := sqlitestore.Open(ctx, options.databasePath)
	if errDatabase != nil {
		return fmt.Errorf("open model core database: %w", errDatabase)
	}
	defer func() {
		if errClose := database.Close(); errClose != nil {
			log.Printf("close model core database: %v", errClose)
		}
	}()
	// configurations persists custom definitions and provider instance configuration.
	// configurations 持久化自定义定义与供应商实例配置。
	configurations, errConfigurations := sqlitestore.NewConfigurationStore(database, protocols, systemDefinitions)
	if errConfigurations != nil {
		return fmt.Errorf("create provider configuration store: %w", errConfigurations)
	}
	// catalogs persists complete provider-scoped model and resource snapshots.
	// catalogs 持久化完整供应商作用域模型与资源快照。
	catalogs, errCatalogs := sqlitestore.NewCatalogStore(database)
	if errCatalogs != nil {
		return fmt.Errorf("create provider catalog store: %w", errCatalogs)
	}
	// metadataDrivers owns trusted provider-native plan and allowance readers independently from execution adapters.
	// metadataDrivers 独立于执行 Adapter 管理受信任的供应商原生套餐与额度读取器。
	metadataDrivers, errMetadataDrivers := provider.NewRegistry(systemDefinitions)
	if errMetadataDrivers != nil {
		return fmt.Errorf("create provider metadata driver registry: %w", errMetadataDrivers)
	}
	antigravityDefinition, existsAntigravityDefinition := systemDefinitions.Lookup(bootstrap.GoogleAntigravityDefinitionID)
	if !existsAntigravityDefinition {
		return errors.New("Google Antigravity system definition is missing")
	}
	// antigravityControlHTTPClient shares CLIProxyAPI's HTTP/1.1-only connection pool across OAuth and metadata calls.
	// antigravityControlHTTPClient 在 OAuth 与元数据调用之间共享 CLIProxyAPI 仅 HTTP/1.1 的连接池。
	antigravityControlHTTPClient := providergoogle.NewAntigravityHTTPClient(30 * time.Second)
	antigravityCatalogDriver, errAntigravityCatalogDriver := providergoogle.NewAntigravityCatalogDriver(antigravityDefinition, secrets, antigravityControlHTTPClient)
	if errAntigravityCatalogDriver != nil {
		return fmt.Errorf("create Antigravity catalog driver: %w", errAntigravityCatalogDriver)
	}
	if errRegisterMetadataDriver := metadataDrivers.Register(antigravityCatalogDriver); errRegisterMetadataDriver != nil {
		return fmt.Errorf("register Antigravity catalog driver: %w", errRegisterMetadataDriver)
	}
	codexDefinition, existsCodexDefinition := systemDefinitions.Lookup(bootstrap.OpenAICodexDefinitionID)
	if !existsCodexDefinition {
		return errors.New("OpenAI Codex system definition is missing")
	}
	codexCatalogDriver, errCodexCatalogDriver := provideropenai.NewCodexCatalogDriver(codexDefinition, secrets)
	if errCodexCatalogDriver != nil {
		return fmt.Errorf("create Codex catalog driver: %w", errCodexCatalogDriver)
	}
	if errRegisterCodexCatalogDriver := metadataDrivers.Register(codexCatalogDriver); errRegisterCodexCatalogDriver != nil {
		return fmt.Errorf("register Codex catalog driver: %w", errRegisterCodexCatalogDriver)
	}
	// metadataRefresh atomically persists provider-native account metadata without requiring model discovery.
	// metadataRefresh 在不要求模型发现的情况下原子持久化供应商原生账号元数据。
	metadataRefresh, errMetadataRefresh := refresh.NewService(configurations, catalogs, metadataDrivers)
	if errMetadataRefresh != nil {
		return fmt.Errorf("create provider metadata refresh service: %w", errMetadataRefresh)
	}
	// managementQueries builds client-safe VulcanCode discovery views.
	// managementQueries 构建客户端安全的 VulcanCode 发现视图。
	managementQueries, errManagementQueries := management.NewQueryService(configurations, catalogs)
	if errManagementQueries != nil {
		return fmt.Errorf("create management query service: %w", errManagementQueries)
	}
	// managementCommands owns durable provider configuration mutations and secret reference lifecycle.
	// managementCommands 管理持久化供应商配置变更和秘密引用生命周期。
	managementCommands, errManagementCommands := management.NewService(configurations, secrets, catalogs)
	if errManagementCommands != nil {
		return fmt.Errorf("create management command service: %w", errManagementCommands)
	}
	// kimiDeviceClient performs bounded Coding Plan device authorization exchanges.
	// kimiDeviceClient 执行有界 Coding Plan 设备授权交换。
	kimiDeviceClient, errKimiDeviceClient := providerkimi.NewDeviceFlowClient(&http.Client{Timeout: 30 * time.Second})
	if errKimiDeviceClient != nil {
		return fmt.Errorf("create Kimi device-flow client: %w", errKimiDeviceClient)
	}
	// kimiDeviceFlows retains only incomplete authorization state in process memory.
	// kimiDeviceFlows 仅在进程内存中保留未完成授权状态。
	kimiDeviceFlows, errKimiDeviceFlows := providerkimi.NewFlowManager(kimiDeviceClient)
	if errKimiDeviceFlows != nil {
		return fmt.Errorf("create Kimi device-flow manager: %w", errKimiDeviceFlows)
	}
	// kimiTokens refreshes completed Coding Plan credentials without exposing provider tokens.
	// kimiTokens 刷新已完成 Coding Plan 凭据且不暴露供应商令牌。
	kimiTokens, errKimiTokens := management.NewKimiTokenService(configurations, secrets, kimiDeviceClient)
	if errKimiTokens != nil {
		return fmt.Errorf("create Kimi token service: %w", errKimiTokens)
	}
	// xaiDeviceClient performs OIDC discovery and bounded Grok CLI device authorization exchanges.
	// xaiDeviceClient 执行 OIDC 发现与有界 Grok CLI 设备授权交换。
	xaiDeviceClient, errXAIDeviceClient := providerxai.NewDeviceFlowClient(&http.Client{Timeout: 30 * time.Second})
	if errXAIDeviceClient != nil {
		return fmt.Errorf("create xAI device-flow client: %w", errXAIDeviceClient)
	}
	// xaiDeviceFlows retains only incomplete xAI authorization state in process memory.
	// xaiDeviceFlows 仅在进程内存中保留未完成 xAI 授权状态。
	xaiDeviceFlows, errXAIDeviceFlows := providerxai.NewFlowManager(xaiDeviceClient)
	if errXAIDeviceFlows != nil {
		return fmt.Errorf("create xAI device-flow manager: %w", errXAIDeviceFlows)
	}
	// xaiTokens refreshes completed xAI credentials without exposing provider tokens.
	// xaiTokens 刷新已完成 xAI 凭据且不暴露供应商 Token。
	xaiTokens, errXAITokens := management.NewXAITokenService(configurations, secrets, xaiDeviceClient)
	if errXAITokens != nil {
		return fmt.Errorf("create xAI token service: %w", errXAITokens)
	}
	// codexDeviceClient performs the exact bounded OpenAI Codex device and token exchanges copied from CLIProxyAPI.
	// codexDeviceClient 执行从 CLIProxyAPI 复制的精确有界 OpenAI Codex 设备与 Token 交换。
	codexDeviceClient, errCodexDeviceClient := provideropenai.NewCodexDeviceFlowClient(&http.Client{Timeout: 30 * time.Second})
	if errCodexDeviceClient != nil {
		return fmt.Errorf("create Codex device-flow client: %w", errCodexDeviceClient)
	}
	// codexDeviceFlows retains only incomplete Codex authorization state in process memory.
	// codexDeviceFlows 仅在进程内存中保留未完成 Codex 授权状态。
	codexDeviceFlows, errCodexDeviceFlows := provideropenai.NewCodexFlowManager(codexDeviceClient)
	if errCodexDeviceFlows != nil {
		return fmt.Errorf("create Codex device-flow manager: %w", errCodexDeviceFlows)
	}
	// codexOAuthClient performs the exact browser PKCE and token exchange copied from CLIProxyAPI.
	// codexOAuthClient 执行从 CLIProxyAPI 复制的精确浏览器 PKCE 与 Token 交换。
	codexOAuthClient, errCodexOAuthClient := provideropenai.NewCodexOAuthClient(&http.Client{Timeout: 30 * time.Second})
	if errCodexOAuthClient != nil {
		return fmt.Errorf("create Codex OAuth client: %w", errCodexOAuthClient)
	}
	// codexOAuthFlows retains only incomplete Codex browser authorization state in process memory.
	// codexOAuthFlows 仅在进程内存中保留未完成 Codex 浏览器授权状态。
	codexOAuthFlows, errCodexOAuthFlows := provideropenai.NewCodexOAuthManager(codexOAuthClient)
	if errCodexOAuthFlows != nil {
		return fmt.Errorf("create Codex OAuth flow manager: %w", errCodexOAuthFlows)
	}
	// codexTokens refreshes completed Codex credentials without exposing provider tokens.
	// codexTokens 刷新已完成 Codex 凭据且不暴露供应商 Token。
	codexTokens, errCodexTokens := management.NewCodexTokenService(configurations, secrets, codexDeviceClient)
	if errCodexTokens != nil {
		return fmt.Errorf("create Codex token service: %w", errCodexTokens)
	}
	// claudeOAuthHTTPClient preserves CLIProxyAPI's Chrome-uTLS fingerprint for OAuth token exchanges.
	// claudeOAuthHTTPClient 为 OAuth Token 交换保留 CLIProxyAPI 的 Chrome-uTLS 指纹。
	claudeOAuthHTTPClient, errClaudeOAuthHTTPClient := provideranthropic.NewClaudeHTTPClient("", 30*time.Second)
	if errClaudeOAuthHTTPClient != nil {
		return fmt.Errorf("create Claude OAuth HTTP client: %w", errClaudeOAuthHTTPClient)
	}
	// claudeOAuthClient performs the copied PKCE, callback, exchange, and refresh behavior.
	// claudeOAuthClient 执行复制的 PKCE、回调、交换与刷新行为。
	claudeOAuthClient, errClaudeOAuthClient := provideranthropic.NewClaudeOAuthClient(claudeOAuthHTTPClient)
	if errClaudeOAuthClient != nil {
		return fmt.Errorf("create Claude OAuth client: %w", errClaudeOAuthClient)
	}
	// claudeOAuthFlows retains only incomplete Claude PKCE and CSRF state in process memory.
	// claudeOAuthFlows 仅在进程内存中保留未完成的 Claude PKCE 与 CSRF 状态。
	claudeOAuthFlows, errClaudeOAuthFlows := provideranthropic.NewClaudeFlowManager(claudeOAuthClient)
	if errClaudeOAuthFlows != nil {
		return fmt.Errorf("create Claude OAuth flow manager: %w", errClaudeOAuthFlows)
	}
	// claudeTokens refreshes completed Claude Code credentials without exposing provider tokens.
	// claudeTokens 刷新已完成 Claude Code 凭据且不暴露供应商 Token。
	claudeTokens, errClaudeTokens := management.NewClaudeTokenService(configurations, secrets, claudeOAuthClient)
	if errClaudeTokens != nil {
		return fmt.Errorf("create Claude token service: %w", errClaudeTokens)
	}
	// antigravityOAuthClient performs copied Google consent, identity, project provisioning, and refresh calls.
	// antigravityOAuthClient 执行复制的 Google 同意授权、身份、项目配置与刷新调用。
	antigravityOAuthClient, errAntigravityOAuthClient := providergoogle.NewAntigravityOAuthClient(antigravityControlHTTPClient)
	if errAntigravityOAuthClient != nil {
		return fmt.Errorf("create Antigravity OAuth client: %w", errAntigravityOAuthClient)
	}
	// antigravityOAuthFlows retains only incomplete CSRF state in process memory.
	// antigravityOAuthFlows 仅在进程内存中保留未完成 CSRF 状态。
	antigravityOAuthFlows, errAntigravityOAuthFlows := providergoogle.NewAntigravityFlowManager(antigravityOAuthClient)
	if errAntigravityOAuthFlows != nil {
		return fmt.Errorf("create Antigravity OAuth flow manager: %w", errAntigravityOAuthFlows)
	}
	// antigravityTokens refreshes completed Antigravity credentials without exposing provider tokens.
	// antigravityTokens 刷新已完成 Antigravity 凭据且不暴露供应商 Token。
	antigravityTokens, errAntigravityTokens := management.NewAntigravityTokenService(configurations, secrets, antigravityOAuthClient)
	if errAntigravityTokens != nil {
		return fmt.Errorf("create Antigravity token service: %w", errAntigravityTokens)
	}
	// modelAccessCommands owns per-instance local model enablement policy.
	// modelAccessCommands 管理每个实例的本地模型启停策略。
	modelAccessCommands, errModelAccessCommands := management.NewModelAccessService(configurations, catalogs)
	if errModelAccessCommands != nil {
		return fmt.Errorf("create model access service: %w", errModelAccessCommands)
	}
	// customCatalogCommands owns complete user-declared model catalogs for custom provider instances.
	// customCatalogCommands 管理自定义供应商实例的完整用户声明模型目录。
	customCatalogCommands, errCustomCatalogCommands := management.NewCustomCatalogService(configurations, catalogs)
	if errCustomCatalogCommands != nil {
		return fmt.Errorf("create custom catalog service: %w", errCustomCatalogCommands)
	}
	// openPlatformTransport resolves raw API keys only for regional Open Platform definitions.
	// openPlatformTransport 仅为区域开放平台定义解析原始 API Key。
	openPlatformTransport, errOpenPlatformTransport := transport.NewClient(&http.Client{Timeout: 5 * time.Minute}, secrets, transport.RetryPolicy{})
	if errOpenPlatformTransport != nil {
		return fmt.Errorf("create Kimi Open Platform transport: %w", errOpenPlatformTransport)
	}
	// codexAccessTokens projects protected OAuth documents to access tokens only during Codex execution.
	// codexAccessTokens 仅在 Codex 执行期间将受保护 OAuth 文档投影为 Access Token。
	codexAccessTokens, errCodexAccessTokens := provideropenai.NewCodexAccessTokenStore(secrets)
	if errCodexAccessTokens != nil {
		return fmt.Errorf("create Codex access-token store: %w", errCodexAccessTokens)
	}
	// codexTransport applies only projected Codex access tokens to outbound requests.
	// codexTransport 仅将投影后的 Codex Access Token 应用于出站请求。
	codexTransport, errCodexTransport := transport.NewClient(&http.Client{Timeout: 5 * time.Minute}, codexAccessTokens, transport.RetryPolicy{})
	if errCodexTransport != nil {
		return fmt.Errorf("create Codex transport: %w", errCodexTransport)
	}
	// claudeAccessTokens projects protected Claude OAuth documents only during execution.
	// claudeAccessTokens 仅在执行期间投影受保护 Claude OAuth 文档。
	claudeAccessTokens, errClaudeAccessTokens := provideranthropic.NewClaudeAccessTokenStore(secrets)
	if errClaudeAccessTokens != nil {
		return fmt.Errorf("create Claude access-token store: %w", errClaudeAccessTokens)
	}
	// claudeExecutionHTTPClient preserves CLIProxyAPI's Chrome-uTLS fingerprint for long-running model requests.
	// claudeExecutionHTTPClient 为长时间模型请求保留 CLIProxyAPI 的 Chrome-uTLS 指纹。
	claudeExecutionHTTPClient, errClaudeExecutionHTTPClient := provideranthropic.NewClaudeHTTPClient("", 5*time.Minute)
	if errClaudeExecutionHTTPClient != nil {
		return fmt.Errorf("create Claude execution HTTP client: %w", errClaudeExecutionHTTPClient)
	}
	// claudeTransport injects only projected Claude access tokens through the uTLS client.
	// claudeTransport 通过 uTLS 客户端仅注入投影后的 Claude Access Token。
	claudeTransport, errClaudeTransport := transport.NewClient(claudeExecutionHTTPClient, claudeAccessTokens, transport.RetryPolicy{})
	if errClaudeTransport != nil {
		return fmt.Errorf("create Claude transport: %w", errClaudeTransport)
	}
	// xaiAccessTokens projects protected OAuth documents to bearer tokens only during xAI account execution.
	// xaiAccessTokens 仅在 xAI 账号执行期间将受保护 OAuth 文档投影为 Bearer Token。
	xaiAccessTokens, errXAIAccessTokens := providerxai.NewAccessTokenStore(secrets)
	if errXAIAccessTokens != nil {
		return fmt.Errorf("create xAI access-token store: %w", errXAIAccessTokens)
	}
	// xaiOAuthTransport applies only projected xAI access tokens to outbound requests.
	// xaiOAuthTransport 仅将投影后的 xAI Access Token 应用于出站请求。
	xaiOAuthTransport, errXAIOAuthTransport := transport.NewClient(&http.Client{Timeout: 5 * time.Minute}, xaiAccessTokens, transport.RetryPolicy{})
	if errXAIOAuthTransport != nil {
		return fmt.Errorf("create xAI OAuth transport: %w", errXAIOAuthTransport)
	}
	// antigravityAccessTokens projects protected OAuth documents to bearer tokens only during execution.
	// antigravityAccessTokens 仅在执行期间将受保护 OAuth 文档投影为 Bearer Token。
	antigravityAccessTokens, errAntigravityAccessTokens := providergoogle.NewAntigravityAccessTokenStore(secrets)
	if errAntigravityAccessTokens != nil {
		return fmt.Errorf("create Antigravity access-token store: %w", errAntigravityAccessTokens)
	}
	// antigravityTransport applies projected access tokens through CLIProxyAPI's HTTP/1.1 and connection-close execution boundary.
	// antigravityTransport 通过 CLIProxyAPI 的 HTTP/1.1 与连接关闭执行边界应用投影后的 Access Token。
	antigravityTransport, errAntigravityTransport := transport.NewClient(providergoogle.NewAntigravityExecutionHTTPClient(5*time.Minute), antigravityAccessTokens, transport.RetryPolicy{})
	if errAntigravityTransport != nil {
		return fmt.Errorf("create Antigravity transport: %w", errAntigravityTransport)
	}
	// vertexAccessTokens exchanges protected RSA service-account documents only at execution time.
	// vertexAccessTokens 仅在执行时交换受保护的 RSA 服务账号文档。
	vertexAccessTokens, errVertexAccessTokens := providergoogle.NewVertexAccessTokenStore(secrets, &http.Client{Timeout: 30 * time.Second})
	if errVertexAccessTokens != nil {
		return fmt.Errorf("create Vertex access-token store: %w", errVertexAccessTokens)
	}
	// vertexTransport applies only projected short-lived Google access tokens to Vertex requests.
	// vertexTransport 仅将投影后的短期 Google Access Token 应用于 Vertex 请求。
	vertexTransport, errVertexTransport := transport.NewClient(&http.Client{Timeout: 5 * time.Minute}, vertexAccessTokens, transport.RetryPolicy{})
	if errVertexTransport != nil {
		return fmt.Errorf("create Vertex transport: %w", errVertexTransport)
	}
	// kimiAccessTokens projects protected refreshable documents to access tokens only at request time.
	// kimiAccessTokens 仅在请求时将受保护可刷新文档投影为 Access Token。
	kimiAccessTokens, errKimiAccessTokens := providerkimi.NewAccessTokenStore(secrets)
	if errKimiAccessTokens != nil {
		return fmt.Errorf("create Kimi access-token store: %w", errKimiAccessTokens)
	}
	// codingTransport applies only the projected Coding Plan access token to outbound requests.
	// codingTransport 仅将投影后的 Coding Plan Access Token 应用于出站请求。
	codingTransport, errCodingTransport := transport.NewClient(&http.Client{Timeout: 5 * time.Minute}, kimiAccessTokens, transport.RetryPolicy{})
	if errCodingTransport != nil {
		return fmt.Errorf("create Kimi Coding transport: %w", errCodingTransport)
	}
	// executionDrivers dispatch by exact provider definition and protocol profile without fallback.
	// executionDrivers 按精确供应商定义和协议 Profile 分派且不进行降级。
	executionDrivers := provider.NewExecutionRegistry()
	if errDrivers := bootstrap.RegisterCLIProxyExecutionDrivers(executionDrivers, openPlatformTransport, codexTransport, claudeTransport, xaiOAuthTransport, antigravityTransport, vertexTransport); errDrivers != nil {
		return fmt.Errorf("register CLIProxyAPI-derived execution drivers: %w", errDrivers)
	}
	if errDrivers := bootstrap.RegisterKimiExecutionDrivers(executionDrivers, openPlatformTransport, codingTransport, secrets); errDrivers != nil {
		return fmt.Errorf("register Kimi execution drivers: %w", errDrivers)
	}
	if errFactory := bootstrap.RegisterCustomExecutionDriverFactory(executionDrivers, openPlatformTransport); errFactory != nil {
		return fmt.Errorf("register custom compatibility execution factory: %w", errFactory)
	}
	// api exposes separated authenticated Vulcan management and call-plane routes.
	// api 暴露相互隔离且经认证的 Vulcan 管理面和调用面路由。
	api, errAPI := httpapi.NewWithControlPlane(executionDrivers, httpapi.ControlPlane{
		Query:                 managementQueries,
		Commands:              managementCommands,
		ModelAccess:           modelAccessCommands,
		CustomCatalogs:        customCatalogCommands,
		MetadataRefresh:       metadataRefresh,
		Protocols:             protocols,
		APIKeys:               controlConfiguration,
		Auth:                  controlConfiguration,
		KimiDeviceFlows:       kimiDeviceFlows,
		KimiTokens:            kimiTokens,
		XAIDeviceFlows:        xaiDeviceFlows,
		XAITokens:             xaiTokens,
		CodexDeviceFlows:      codexDeviceFlows,
		CodexOAuthFlows:       codexOAuthFlows,
		CodexTokens:           codexTokens,
		ClaudeOAuthFlows:      claudeOAuthFlows,
		ClaudeTokens:          claudeTokens,
		AntigravityOAuthFlows: antigravityOAuthFlows,
		AntigravityTokens:     antigravityTokens,
	})
	if errAPI != nil {
		return fmt.Errorf("create HTTP API: %w", errAPI)
	}
	// listener binds before the process announces readiness information.
	// listener 在进程公布监听信息前完成绑定。
	listener, errListen := net.Listen("tcp", options.listenAddress)
	if errListen != nil {
		return fmt.Errorf("listen on %s: %w", options.listenAddress, errListen)
	}
	defer func() {
		if errClose := listener.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) {
			log.Printf("close listener: %v", errClose)
		}
	}()

	// server owns the standard library HTTP lifecycle.
	// server 管理标准库 HTTP 生命周期。
	server := &http.Server{Handler: api.Handler()}
	// serveErrors receives the terminal serve result exactly once.
	// serveErrors 只接收一次最终服务结果。
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()
	log.Printf("vulcan-model-core listening on %s", listener.Addr())

	select {
	case errServe := <-serveErrors:
		if errServe != nil && !errors.Is(errServe, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP API: %w", errServe)
		}
		return nil
	case <-ctx.Done():
		// shutdownContext bounds graceful HTTP shutdown during process termination.
		// shutdownContext 在进程终止期间限制优雅 HTTP 关闭时间。
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if errShutdown := server.Shutdown(shutdownContext); errShutdown != nil {
			return fmt.Errorf("shutdown HTTP API: %w", errShutdown)
		}
		// errServe is the terminal server result after graceful shutdown.
		// errServe 是优雅关闭后的最终服务结果。
		errServe := <-serveErrors
		if errServe != nil && !errors.Is(errServe, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP API: %w", errServe)
		}
		return nil
	}
}
