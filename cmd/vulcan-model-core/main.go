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
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
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
	if errDrivers := bootstrap.RegisterKimiExecutionDrivers(executionDrivers, openPlatformTransport, codingTransport); errDrivers != nil {
		return fmt.Errorf("register Kimi execution drivers: %w", errDrivers)
	}
	// api exposes separated authenticated Vulcan management and call-plane routes.
	// api 暴露相互隔离且经认证的 Vulcan 管理面和调用面路由。
	api, errAPI := httpapi.NewWithControlPlane(executionDrivers, httpapi.ControlPlane{
		Query:           managementQueries,
		Commands:        managementCommands,
		ModelAccess:     modelAccessCommands,
		CustomCatalogs:  customCatalogCommands,
		Protocols:       protocols,
		APIKeys:         controlConfiguration,
		Auth:            controlConfiguration,
		KimiDeviceFlows: kimiDeviceFlows,
		KimiTokens:      kimiTokens,
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
