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
	"path/filepath"
	"syscall"
	"time"

	"github.com/OpenVulcan/vulcan-model-core/internal/access"
	"github.com/OpenVulcan/vulcan-model-core/internal/bootstrap"
	"github.com/OpenVulcan/vulcan-model-core/internal/catalogruntime"
	executioncore "github.com/OpenVulcan/vulcan-model-core/internal/execution"
	"github.com/OpenVulcan/vulcan-model-core/internal/httpapi"
	"github.com/OpenVulcan/vulcan-model-core/internal/inputplan"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider"
	provideralibaba "github.com/OpenVulcan/vulcan-model-core/internal/provider/alibaba"
	provideranthropic "github.com/OpenVulcan/vulcan-model-core/internal/provider/anthropic"
	providerdeepseek "github.com/OpenVulcan/vulcan-model-core/internal/provider/deepseek"
	providergoogle "github.com/OpenVulcan/vulcan-model-core/internal/provider/google"
	providerkimi "github.com/OpenVulcan/vulcan-model-core/internal/provider/kimi"
	providerminimax "github.com/OpenVulcan/vulcan-model-core/internal/provider/minimax"
	provideropenai "github.com/OpenVulcan/vulcan-model-core/internal/provider/openai"
	providertavily "github.com/OpenVulcan/vulcan-model-core/internal/provider/tavily"
	"github.com/OpenVulcan/vulcan-model-core/internal/provider/transport"
	providerxai "github.com/OpenVulcan/vulcan-model-core/internal/provider/xai"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/refresh"
	"github.com/OpenVulcan/vulcan-model-core/internal/resolve"
	"github.com/OpenVulcan/vulcan-model-core/internal/resource"
	"github.com/OpenVulcan/vulcan-model-core/internal/routertool"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimeconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/runtimefeedback"
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
	// defaultResourceDirectory is the local fallback overridden by the prescribed user-level launcher path.
	// defaultResourceDirectory 是由规定用户级启动路径覆盖的本地回退目录。
	defaultResourceDirectory = "vulcan-model-core.resources"
	// defaultMaximumResourceBytes is the per-object ingestion ceiling.
	// defaultMaximumResourceBytes 是单对象接收上限。
	defaultMaximumResourceBytes int64 = 512 << 20
	// defaultMaximumReadyResourceBytes is the aggregate ready-object quota.
	// defaultMaximumReadyResourceBytes 是全部就绪对象总配额。
	defaultMaximumReadyResourceBytes int64 = 20 << 30
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
	// resourceDirectory is the user-level Router resource root.
	// resourceDirectory 是用户级 Router 资源根目录。
	resourceDirectory string
	// tlsCertificatePath optionally enables HTTPS with this PEM certificate chain.
	// tlsCertificatePath 可选地使用此 PEM 证书链启用 HTTPS。
	tlsCertificatePath string
	// tlsPrivateKeyPath is the matching PEM private key and must be configured together with the certificate.
	// tlsPrivateKeyPath 是匹配的 PEM 私钥且必须与证书同时配置。
	tlsPrivateKeyPath string
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
	flags.StringVar(&options.resourceDirectory, "resource-directory", defaultResourceDirectory, "Local Router resource directory")
	flags.StringVar(&options.tlsCertificatePath, "tls-cert", "", "Optional TLS certificate chain path")
	flags.StringVar(&options.tlsPrivateKeyPath, "tls-key", "", "Optional TLS private key path")
	if errParse := flags.Parse(args); errParse != nil {
		return runOptions{}, fmt.Errorf("parse command flags: %w", errParse)
	}
	if (options.tlsCertificatePath == "") != (options.tlsPrivateKeyPath == "") {
		return runOptions{}, errors.New("tls-cert and tls-key must be configured together")
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
	// database owns durable user configuration, secrets metadata, and custom-provider catalogs.
	// database 管理持久化用户配置、Secret 元数据与自定义供应商目录。
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
	// persistedCatalogs owns only user-created custom-provider model and resource snapshots.
	// persistedCatalogs 仅拥有用户创建的自定义供应商模型与资源快照。
	persistedCatalogs, errPersistedCatalogs := sqlitestore.NewCatalogStore(database)
	if errPersistedCatalogs != nil {
		return fmt.Errorf("create persistent custom-provider catalog store: %w", errPersistedCatalogs)
	}
	purgedSystemCatalogs, errPurgeSystemCatalogs := catalogruntime.PurgePersistedSystemCatalogs(ctx, configurations, persistedCatalogs)
	if errPurgeSystemCatalogs != nil {
		return fmt.Errorf("purge historical persisted system catalogs: %w", errPurgeSystemCatalogs)
	}
	if purgedSystemCatalogs > 0 {
		log.Printf("purged %d historical persisted system catalog(s)", purgedSystemCatalogs)
	}
	// catalogs keeps code-owned system catalogs in memory and delegates only custom catalogs to SQLite.
	// catalogs 将代码拥有的系统目录保留在内存，并仅将自定义目录委托给 SQLite。
	catalogs, errCatalogs := catalogruntime.New(configurations, persistedCatalogs)
	if errCatalogs != nil {
		return fmt.Errorf("create ownership-aware catalog store: %w", errCatalogs)
	}
	// routingStates persists inherited scheduling policy and exact credential-model cooldowns.
	// routingStates 持久化继承的调度策略与精确凭据模型冷却状态。
	routingStates, errRoutingStates := sqlitestore.NewRoutingStateStore(database)
	if errRoutingStates != nil {
		return fmt.Errorf("create routing state store: %w", errRoutingStates)
	}
	// reconciledMiniMaxOrigins collapses historical per-action endpoint copies before any resolver or management query reads them.
	// reconciledMiniMaxOrigins 在任何 Resolver 或管理查询读取前收敛历史 MiniMax 按动作复制的端点。
	reconciledMiniMaxOrigins, errReconcileMiniMaxOrigins := management.ReconcileMiniMaxSharedOrigins(ctx, configurations)
	if errReconcileMiniMaxOrigins != nil {
		return fmt.Errorf("reconcile persisted MiniMax shared Origins: %w", errReconcileMiniMaxOrigins)
	}
	if reconciledMiniMaxOrigins > 0 {
		log.Printf("reconciled %d persisted MiniMax provider Origin(s)", reconciledMiniMaxOrigins)
	}
	loadedSystemCatalogs, errLoadSystemCatalogs := management.LoadSystemCatalogs(ctx, configurations, catalogs)
	if errLoadSystemCatalogs != nil {
		return fmt.Errorf("load runtime system catalogs: %w", errLoadSystemCatalogs)
	}
	if loadedSystemCatalogs > 0 {
		log.Printf("loaded %d code-owned system catalog(s) into runtime memory", loadedSystemCatalogs)
	}
	// reconciledAlibabaCatalogs upgrades historical Alibaba snapshots to the complete explicit-policy baseline before any resolver or management query reads them.
	// reconciledAlibabaCatalogs 在任何 Resolver 或管理查询读取历史 Alibaba 快照前，将其升级到完整的显式策略基线。
	reconciledAlibabaCatalogs, errReconcileAlibabaCatalogs := management.ReconcileAlibabaSystemCatalogs(ctx, configurations, catalogs)
	if errReconcileAlibabaCatalogs != nil {
		return fmt.Errorf("reconcile persisted Alibaba system catalogs: %w", errReconcileAlibabaCatalogs)
	}
	if reconciledAlibabaCatalogs > 0 {
		log.Printf("reconciled %d persisted Alibaba catalog(s) to the complete policy baseline", reconciledAlibabaCatalogs)
	}
	// reconciledTavilyCatalogs adds the typed Extract contract to historical Tavily snapshots before management discovery.
	// reconciledTavilyCatalogs 在管理发现前为历史 Tavily 快照补充类型化 Extract 合同。
	reconciledTavilyCatalogs, errReconcileTavilyCatalogs := management.ReconcileTavilyExtractCatalogs(ctx, configurations, catalogs)
	if errReconcileTavilyCatalogs != nil {
		return fmt.Errorf("reconcile persisted Tavily Extract catalogs: %w", errReconcileTavilyCatalogs)
	}
	if reconciledTavilyCatalogs > 0 {
		log.Printf("reconciled %d persisted Tavily catalog(s) with Extract support", reconciledTavilyCatalogs)
	}
	// reconciledKimiCatalogs upgrades historical multi-protocol Kimi snapshots to the current single Chat contract before any resolver reads them.
	// reconciledKimiCatalogs 在任何 Resolver 读取历史多协议 Kimi 快照前，将其升级到当前唯一 Chat 合同。
	reconciledKimiCatalogs, errReconcileKimiCatalogs := management.ReconcileKimiSystemCatalogs(ctx, configurations, catalogs)
	if errReconcileKimiCatalogs != nil {
		return fmt.Errorf("reconcile persisted Kimi system catalogs: %w", errReconcileKimiCatalogs)
	}
	if reconciledKimiCatalogs > 0 {
		log.Printf("reconciled %d persisted Kimi catalog(s) to the single Chat protocol", reconciledKimiCatalogs)
	}
	// reconciledCustomCatalogs restores protocol-guaranteed synchronous and streaming modes omitted by historical custom model builders.
	// reconciledCustomCatalogs 恢复历史自定义模型构建器遗漏的协议保证同步与流式模式。
	reconciledCustomCatalogs, errReconcileCustomCatalogs := management.ReconcileCustomConversationCatalogs(ctx, configurations, catalogs)
	if errReconcileCustomCatalogs != nil {
		return fmt.Errorf("reconcile persisted custom provider delivery modes: %w", errReconcileCustomCatalogs)
	}
	if reconciledCustomCatalogs > 0 {
		log.Printf("reconciled %d persisted custom provider catalog(s) with executable delivery modes", reconciledCustomCatalogs)
	}
	// reconciledCodexCatalogs removes historical unknown-plan privilege before any target can be resolved.
	// reconciledCodexCatalogs 在任何 Target 可被解析前删除历史未知套餐权限。
	reconciledCodexCatalogs, errReconcileCodexCatalogs := management.ReconcileCodexUnknownPlanEntitlements(ctx, configurations, catalogs)
	if errReconcileCodexCatalogs != nil {
		return fmt.Errorf("reconcile persisted Codex unknown-plan entitlements: %w", errReconcileCodexCatalogs)
	}
	if reconciledCodexCatalogs > 0 {
		log.Printf("reconciled %d persisted Codex catalog(s) with unknown plan entitlements", reconciledCodexCatalogs)
	}
	// resourceMetadata persists non-binary lifecycle records in the shared SQLite database.
	// resourceMetadata 在共享 SQLite 数据库中持久化非二进制生命周期记录。
	resourceMetadata, errResourceMetadata := sqlitestore.NewResourceStore(database)
	if errResourceMetadata != nil {
		return fmt.Errorf("create resource metadata store: %w", errResourceMetadata)
	}
	// assetBindings persists exact-target provider handles and participates in resource cleanup.
	// assetBindings 持久化精确 Target 供应商句柄并参与资源清理。
	assetBindings, errAssetBindings := sqlitestore.NewAssetBindingStore(database)
	if errAssetBindings != nil {
		return fmt.Errorf("create provider asset binding store: %w", errAssetBindings)
	}
	// miniMaxAccessTokens projects either a raw API key or a protected OAuth document for every MiniMax data-plane action.
	// miniMaxAccessTokens 为每个 MiniMax 数据面动作投影原始 API Key 或受保护 OAuth 文档。
	miniMaxAccessTokens, errMiniMaxAccessTokens := providerminimax.NewAccessTokenStore(secrets)
	if errMiniMaxAccessTokens != nil {
		return fmt.Errorf("create MiniMax access-token store: %w", errMiniMaxAccessTokens)
	}
	// miniMaxFileUploader owns the standalone FileSDK lifecycle and is not a VLM input carrier.
	// miniMaxFileUploader 管理独立 FileSDK 生命周期，且不作为 VLM 输入载体。
	miniMaxFileUploader, errMiniMaxFileUploader := providerminimax.NewFileUploader(configurations, miniMaxAccessTokens, &http.Client{Timeout: 5 * time.Minute})
	if errMiniMaxFileUploader != nil {
		return fmt.Errorf("create MiniMax file uploader: %w", errMiniMaxFileUploader)
	}
	// alibabaOSSDefinitionIDs is the exact CN set with verified temporary-upload request paths.
	// alibabaOSSDefinitionIDs 是已验证临时上传请求路径的精确 CN 集合。
	alibabaOSSDefinitionIDs := []string{bootstrap.AlibabaModelStudioCNDefinitionID, bootstrap.AlibabaTokenPlanPersonalCNDefinitionID}
	// alibabaOSSUploader owns temporary 48-hour oss:// materializations for the proven CN products.
	// alibabaOSSUploader 管理已证明 CN 产品的临时 48 小时 oss:// 物化结果。
	alibabaOSSUploader, errAlibabaOSSUploader := provideralibaba.NewOSSUploader(configurations, secrets, &http.Client{Timeout: 5 * time.Minute}, alibabaOSSDefinitionIDs, provideralibaba.OSSUploaderOptions{})
	if errAlibabaOSSUploader != nil {
		return fmt.Errorf("create Alibaba OSS uploader: %w", errAlibabaOSSUploader)
	}
	// assetUploaders routes exact provider definitions without cross-provider fallback.
	// assetUploaders 按精确供应商定义路由且不进行跨供应商回退。
	assetUploaders, errAssetUploaders := resource.NewAssetUploaderRouter(
		resource.AssetUploaderRoute{ProviderDefinitionIDs: []string{bootstrap.MiniMaxGlobalDefinitionID, bootstrap.MiniMaxCNDefinitionID}, Uploader: miniMaxFileUploader},
		resource.AssetUploaderRoute{ProviderDefinitionIDs: alibabaOSSDefinitionIDs, Uploader: alibabaOSSUploader},
	)
	if errAssetUploaders != nil {
		return fmt.Errorf("create provider asset uploader router: %w", errAssetUploaders)
	}
	// assetBindingCleaner dispatches exact provider cleanup before local resource removal.
	// assetBindingCleaner 在删除本地资源前分派精确供应商清理。
	assetBindingCleaner, errAssetBindingCleaner := resource.NewAssetBindingCleaner(assetBindings, secrets, assetUploaders)
	if errAssetBindingCleaner != nil {
		return fmt.Errorf("create provider asset binding cleaner: %w", errAssetBindingCleaner)
	}
	// resourceService owns verified filesystem objects under the explicit user-level root.
	// resourceService 在明确用户级根目录下管理已验证文件系统对象。
	resourceService, errResourceService := resource.NewService(resourceMetadata, resource.ServiceOptions{Root: filepath.Clean(options.resourceDirectory), MaxObjectBytes: defaultMaximumResourceBytes, MaxReadyBytes: defaultMaximumReadyResourceBytes, DefaultTTL: 24 * time.Hour, MaxTTL: 30 * 24 * time.Hour, BindingCleaner: assetBindingCleaner})
	if errResourceService != nil {
		return fmt.Errorf("create Router resource service: %w", errResourceService)
	}
	// resourceImporter owns proxy-free URL acquisition and bounded Base64 decoding.
	// resourceImporter 拥有无代理 URL 获取与受限 Base64 解码。
	resourceImporter, errResourceImporter := resource.NewImporter(resourceService, resource.ImporterOptions{RequestTimeout: 2 * time.Minute, ResponseHeaderTimeout: 30 * time.Second, MaxRedirects: 5})
	if errResourceImporter != nil {
		return fmt.Errorf("create Router resource importer: %w", errResourceImporter)
	}
	// resourceGateway exposes the complete owner-scoped call-plane resource boundary.
	// resourceGateway 暴露完整所有者作用域调用面资源边界。
	resourceGateway, errResourceGateway := resource.NewGateway(resourceService, resourceImporter)
	if errResourceGateway != nil {
		return fmt.Errorf("create Router resource gateway: %w", errResourceGateway)
	}
	// targetResolver combines exact provider configuration and catalog snapshots for planning and execution.
	// targetResolver 为规划与执行组合精确供应商配置及目录快照。
	targetResolver, errTargetResolver := resolve.NewWithRuntimeState(configurations, catalogs, routingStates)
	if errTargetResolver != nil {
		return fmt.Errorf("create provider target resolver: %w", errTargetResolver)
	}
	// routerToolBindings persists explicit standard-tool service backends.
	// routerToolBindings 持久化显式标准工具服务后端。
	routerToolBindings, errRouterToolBindings := sqlitestore.NewRouterToolStore(database)
	if errRouterToolBindings != nil {
		return fmt.Errorf("create Router tool binding store: %w", errRouterToolBindings)
	}
	// routerToolResolver freezes one ready child target before parent execution admission.
	// routerToolResolver 在父执行接收前冻结一个就绪子 Target。
	routerToolResolver, errRouterToolResolver := routertool.NewResolver(routerToolBindings, targetResolver)
	if errRouterToolResolver != nil {
		return fmt.Errorf("create Router tool resolver: %w", errRouterToolResolver)
	}
	// inputPlanStore persists conditional media decisions across process restarts.
	// inputPlanStore 跨进程重启持久化条件媒体决策。
	inputPlanStore, errInputPlanStore := sqlitestore.NewInputPlanStore(database)
	if errInputPlanStore != nil {
		return fmt.Errorf("create input plan store: %w", errInputPlanStore)
	}
	// inputPlans freezes one legal media path and rejects capability drift before execution.
	// inputPlans 冻结一条合法媒体路径并在执行前拒绝能力漂移。
	inputPlans, errInputPlans := inputplan.NewService(targetResolver, resourceService, inputPlanStore, inputplan.ServiceOptions{TTL: 10 * time.Minute})
	if errInputPlans != nil {
		return fmt.Errorf("create input plan service: %w", errInputPlans)
	}
	// executionStore persists lifecycle, idempotency, event replay, and recovery snapshots.
	// executionStore 持久化生命周期、幂等、事件回放与恢复快照。
	executionStore, errExecutionStore := sqlitestore.NewExecutionStore(database, secrets)
	if errExecutionStore != nil {
		return fmt.Errorf("create execution store: %w", errExecutionStore)
	}
	// inputMaterializer realizes code-declared inline, direct URL, and registered provider-asset plans.
	// inputMaterializer 实现代码声明的内联、直连 URL 与已注册供应商资产方案。
	inputMaterializer, errInputMaterializer := resource.NewMaterializer(resourceService, assetBindings, secrets, assetUploaders, resource.MaterializerOptions{})
	if errInputMaterializer != nil {
		return fmt.Errorf("create input materializer: %w", errInputMaterializer)
	}
	// metadataDrivers owns trusted provider-native plan and allowance readers independently from execution adapters.
	// metadataDrivers 独立于执行 Adapter 管理受信任的供应商原生套餐与额度读取器。
	metadataDrivers, errMetadataDrivers := provider.NewRegistry(systemDefinitions)
	if errMetadataDrivers != nil {
		return fmt.Errorf("create provider metadata driver registry: %w", errMetadataDrivers)
	}
	tavilyDefinition, existsTavilyDefinition := systemDefinitions.Lookup(bootstrap.TavilySearchDefinitionID)
	if !existsTavilyDefinition {
		return errors.New("Tavily system definition is missing")
	}
	// tavilyMetadataDriver reads the documented account plan and credit counters without inventing reset times.
	// tavilyMetadataDriver 读取文档化账号套餐与 Credit 计数，且不虚构重置时间。
	tavilyMetadataDriver, errTavilyMetadataDriver := providertavily.NewMetadataDriver(tavilyDefinition, secrets, &http.Client{Timeout: 30 * time.Second})
	if errTavilyMetadataDriver != nil {
		return fmt.Errorf("create Tavily metadata driver: %w", errTavilyMetadataDriver)
	}
	if errRegisterTavilyMetadata := metadataDrivers.Register(tavilyMetadataDriver); errRegisterTavilyMetadata != nil {
		return fmt.Errorf("register Tavily metadata driver: %w", errRegisterTavilyMetadata)
	}
	deepSeekDefinition, existsDeepSeekDefinition := systemDefinitions.Lookup(bootstrap.DeepSeekAPIDefinitionID)
	if !existsDeepSeekDefinition {
		return errors.New("DeepSeek system definition is missing")
	}
	// deepSeekAllowanceDriver reads the official balance endpoint without exposing protected API keys.
	// deepSeekAllowanceDriver 读取官方余额端点且不暴露受保护 API Key。
	deepSeekAllowanceDriver, errDeepSeekAllowanceDriver := providerdeepseek.NewAllowanceDriver(deepSeekDefinition, secrets, &http.Client{Timeout: 30 * time.Second})
	if errDeepSeekAllowanceDriver != nil {
		return fmt.Errorf("create DeepSeek allowance driver: %w", errDeepSeekAllowanceDriver)
	}
	if errRegisterDeepSeekAllowance := metadataDrivers.Register(deepSeekAllowanceDriver); errRegisterDeepSeekAllowance != nil {
		return fmt.Errorf("register DeepSeek allowance driver: %w", errRegisterDeepSeekAllowance)
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
	codexCatalogDriver, errCodexCatalogDriver := provideropenai.NewCodexCatalogDriver(codexDefinition, secrets, &http.Client{Timeout: 30 * time.Second})
	if errCodexCatalogDriver != nil {
		return fmt.Errorf("create Codex catalog driver: %w", errCodexCatalogDriver)
	}
	if errRegisterCodexCatalogDriver := metadataDrivers.Register(codexCatalogDriver); errRegisterCodexCatalogDriver != nil {
		return fmt.Errorf("register Codex catalog driver: %w", errRegisterCodexCatalogDriver)
	}
	kimiCodingDefinition, existsKimiCodingDefinition := systemDefinitions.Lookup(bootstrap.KimiCodingDefinitionID)
	if !existsKimiCodingDefinition {
		return errors.New("Kimi Coding Plan system definition is missing")
	}
	// kimiAllowanceDriver reads the proven Coding Plan account endpoint for plan, entitlement, and usage facts.
	// kimiAllowanceDriver 读取已验证的 Coding Plan 账号入口以获得套餐、授权与用量事实。
	kimiAllowanceDriver, errKimiAllowanceDriver := providerkimi.NewAllowanceDriver(kimiCodingDefinition, secrets, &http.Client{Timeout: 30 * time.Second})
	if errKimiAllowanceDriver != nil {
		return fmt.Errorf("create Kimi allowance driver: %w", errKimiAllowanceDriver)
	}
	if errRegisterKimiAllowance := metadataDrivers.Register(kimiAllowanceDriver); errRegisterKimiAllowance != nil {
		return fmt.Errorf("register Kimi allowance driver: %w", errRegisterKimiAllowance)
	}
	// miniMaxAllowanceDrivers read Token Plan windows only from each explicitly selected regional Definition.
	// miniMaxAllowanceDrivers 仅从每个显式选择的区域 Definition 读取 Token Plan 窗口。
	for _, miniMaxDefinitionID := range []string{bootstrap.MiniMaxGlobalDefinitionID, bootstrap.MiniMaxCNDefinitionID} {
		miniMaxDefinition, existsMiniMaxDefinition := systemDefinitions.Lookup(miniMaxDefinitionID)
		if !existsMiniMaxDefinition {
			return fmt.Errorf("MiniMax system definition %q is missing", miniMaxDefinitionID)
		}
		miniMaxAllowanceDriver, errMiniMaxAllowanceDriver := providerminimax.NewAllowanceDriver(miniMaxDefinition, miniMaxAccessTokens, &http.Client{Timeout: 30 * time.Second})
		if errMiniMaxAllowanceDriver != nil {
			return fmt.Errorf("create MiniMax allowance driver %q: %w", miniMaxDefinitionID, errMiniMaxAllowanceDriver)
		}
		if errRegisterMiniMaxAllowance := metadataDrivers.Register(miniMaxAllowanceDriver); errRegisterMiniMaxAllowance != nil {
			return fmt.Errorf("register MiniMax allowance driver %q: %w", miniMaxDefinitionID, errRegisterMiniMaxAllowance)
		}
	}
	claudeCodeDefinition, existsClaudeCodeDefinition := systemDefinitions.Lookup(bootstrap.AnthropicClaudeCodeDefinitionID)
	if !existsClaudeCodeDefinition {
		return errors.New("Claude Code system definition is missing")
	}
	// claudeAllowanceDriver reads the proven OAuth usage windows and extra-use balance.
	// claudeAllowanceDriver 读取已验证的 OAuth 用量窗口与额外用量余额。
	claudeAllowanceDriver, errClaudeAllowanceDriver := provideranthropic.NewAllowanceDriver(claudeCodeDefinition, secrets, &http.Client{Timeout: 30 * time.Second})
	if errClaudeAllowanceDriver != nil {
		return fmt.Errorf("create Claude allowance driver: %w", errClaudeAllowanceDriver)
	}
	if errRegisterClaudeAllowance := metadataDrivers.Register(claudeAllowanceDriver); errRegisterClaudeAllowance != nil {
		return fmt.Errorf("register Claude allowance driver: %w", errRegisterClaudeAllowance)
	}
	xaiAccountDefinition, existsXAIAccountDefinition := systemDefinitions.Lookup(bootstrap.XAIOAuthDefinitionID)
	if !existsXAIAccountDefinition {
		return errors.New("xAI account system definition is missing")
	}
	// xaiAllowanceDriver reads the proven Grok CLI monthly billing data.
	// xaiAllowanceDriver 读取已验证的 Grok CLI 月度计费数据。
	xaiAllowanceDriver, errXAIAllowanceDriver := providerxai.NewAllowanceDriver(xaiAccountDefinition, secrets, &http.Client{Timeout: 30 * time.Second})
	if errXAIAllowanceDriver != nil {
		return fmt.Errorf("create xAI allowance driver: %w", errXAIAllowanceDriver)
	}
	if errRegisterXAIAllowance := metadataDrivers.Register(xaiAllowanceDriver); errRegisterXAIAllowance != nil {
		return fmt.Errorf("register xAI allowance driver: %w", errRegisterXAIAllowance)
	}
	// managementQueries builds client-safe VulcanCode discovery views.
	// managementQueries 构建客户端安全的 VulcanCode 发现视图。
	managementQueries, errManagementQueries := management.NewQueryServiceWithRuntimeState(configurations, catalogs, routingStates)
	if errManagementQueries != nil {
		return fmt.Errorf("create management query service: %w", errManagementQueries)
	}
	// managementCommands owns durable provider configuration mutations and secret reference lifecycle.
	// managementCommands 管理持久化供应商配置变更和秘密引用生命周期。
	managementCommands, errManagementCommands := management.NewService(configurations, secrets, catalogs)
	if errManagementCommands != nil {
		return fmt.Errorf("create management command service: %w", errManagementCommands)
	}
	// routingManagement owns global and instance scheduling policy plus manual plan mutations.
	// routingManagement 管理全局与实例调度策略以及人工套餐变更。
	routingManagement, errRoutingManagement := management.NewRoutingService(configurations, catalogs, routingStates)
	if errRoutingManagement != nil {
		return fmt.Errorf("create routing management service: %w", errRoutingManagement)
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
	// miniMaxGlobalDeviceClient performs OAuth exchanges only against the Global account Origin.
	// miniMaxGlobalDeviceClient 仅针对 Global 账号 Origin 执行 OAuth 交换。
	miniMaxGlobalDeviceClient, errMiniMaxGlobalDeviceClient := providerminimax.NewDeviceFlowClient(&http.Client{Timeout: 30 * time.Second}, providerminimax.GlobalOAuthRegion())
	if errMiniMaxGlobalDeviceClient != nil {
		return fmt.Errorf("create MiniMax Global device-flow client: %w", errMiniMaxGlobalDeviceClient)
	}
	// miniMaxCNDeviceClient performs OAuth exchanges only against the CN account Origin.
	// miniMaxCNDeviceClient 仅针对 CN 账号 Origin 执行 OAuth 交换。
	miniMaxCNDeviceClient, errMiniMaxCNDeviceClient := providerminimax.NewDeviceFlowClient(&http.Client{Timeout: 30 * time.Second}, providerminimax.CNOAuthRegion())
	if errMiniMaxCNDeviceClient != nil {
		return fmt.Errorf("create MiniMax CN device-flow client: %w", errMiniMaxCNDeviceClient)
	}
	// miniMaxGlobalFlows owns only Global-site transient authorization state.
	// miniMaxGlobalFlows 仅管理 Global 站点的临时授权状态。
	miniMaxGlobalFlows, errMiniMaxGlobalFlows := providerminimax.NewFlowManager(miniMaxGlobalDeviceClient)
	if errMiniMaxGlobalFlows != nil {
		return fmt.Errorf("create MiniMax Global flow manager: %w", errMiniMaxGlobalFlows)
	}
	// miniMaxCNFlows owns only CN-site transient authorization state.
	// miniMaxCNFlows 仅管理 CN 站点的临时授权状态。
	miniMaxCNFlows, errMiniMaxCNFlows := providerminimax.NewFlowManager(miniMaxCNDeviceClient)
	if errMiniMaxCNFlows != nil {
		return fmt.Errorf("create MiniMax CN flow manager: %w", errMiniMaxCNFlows)
	}
	// miniMaxDeviceFlows dispatches only from the explicit region selected before authorization.
	// miniMaxDeviceFlows 仅根据授权前显式选择的区域进行分派。
	miniMaxDeviceFlows, errMiniMaxDeviceFlows := providerminimax.NewRegionalFlowManager(miniMaxGlobalFlows, miniMaxCNFlows)
	if errMiniMaxDeviceFlows != nil {
		return fmt.Errorf("create MiniMax regional flow manager: %w", errMiniMaxDeviceFlows)
	}
	// miniMaxTokenClient refreshes through the immutable region stored in the protected document.
	// miniMaxTokenClient 通过受保护文档中不可变的区域刷新 Token。
	miniMaxTokenClient, errMiniMaxTokenClient := providerminimax.NewRegionalTokenClient(miniMaxGlobalDeviceClient, miniMaxCNDeviceClient)
	if errMiniMaxTokenClient != nil {
		return fmt.Errorf("create MiniMax regional token client: %w", errMiniMaxTokenClient)
	}
	// miniMaxTokens persists exact-region OAuth refresh results without exposing token material.
	// miniMaxTokens 在不暴露 Token 材料的情况下持久化精确区域 OAuth 刷新结果。
	miniMaxTokens, errMiniMaxTokens := management.NewMiniMaxTokenService(configurations, secrets, miniMaxTokenClient)
	if errMiniMaxTokens != nil {
		return fmt.Errorf("create MiniMax token service: %w", errMiniMaxTokens)
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
	// credentialRefreshers bind each refreshable system definition to its existing protected token lifecycle service.
	// credentialRefreshers 将每个可刷新系统定义绑定到现有的受保护令牌生命周期服务。
	credentialRefreshers := map[string]refresh.CredentialRefresher{
		bootstrap.KimiCodingDefinitionID:          kimiTokens,
		bootstrap.MiniMaxGlobalDefinitionID:       miniMaxTokens,
		bootstrap.MiniMaxCNDefinitionID:           miniMaxTokens,
		bootstrap.XAIOAuthDefinitionID:            xaiTokens,
		bootstrap.OpenAICodexDefinitionID:         codexTokens,
		bootstrap.AnthropicClaudeCodeDefinitionID: claudeTokens,
		bootstrap.GoogleAntigravityDefinitionID:   antigravityTokens,
	}
	// metadataRefresh atomically persists provider-native account metadata after refreshing expiring provider tokens.
	// metadataRefresh 在刷新将到期的供应商令牌后原子持久化供应商原生账号元数据。
	metadataRefresh, errMetadataRefresh := refresh.NewServiceWithCredentialRefreshers(configurations, catalogs, metadataDrivers, credentialRefreshers)
	if errMetadataRefresh != nil {
		return fmt.Errorf("create provider metadata refresh service: %w", errMetadataRefresh)
	}
	// metadataRefreshCoordinator deduplicates mutation triggers and performs bounded jittered background refreshes.
	// metadataRefreshCoordinator 对变更触发去重，并执行有界且带抖动的后台刷新。
	metadataRefreshCoordinator, errMetadataRefreshCoordinator := refresh.NewCoordinator(configurations, metadataRefresh, refresh.CoordinatorOptions{})
	if errMetadataRefreshCoordinator != nil {
		return fmt.Errorf("create provider metadata refresh coordinator: %w", errMetadataRefreshCoordinator)
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
	// miniMaxTransport applies projected API-key or OAuth access-token values without changing the selected regional endpoint.
	// miniMaxTransport 应用投影后的 API Key 或 OAuth Access Token，且不更改选定区域入口。
	miniMaxTransport, errMiniMaxTransport := transport.NewClient(&http.Client{Timeout: 5 * time.Minute}, miniMaxAccessTokens, transport.RetryPolicy{})
	if errMiniMaxTransport != nil {
		return fmt.Errorf("create MiniMax transport: %w", errMiniMaxTransport)
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
	if errDrivers := bootstrap.RegisterAlibabaExecutionDrivers(executionDrivers, openPlatformTransport, resourceImporter); errDrivers != nil {
		return fmt.Errorf("register Alibaba execution drivers: %w", errDrivers)
	}
	if errDrivers := bootstrap.RegisterOpenRouterExecutionDrivers(executionDrivers, openPlatformTransport); errDrivers != nil {
		return fmt.Errorf("register OpenRouter execution drivers: %w", errDrivers)
	}
	if errDrivers := bootstrap.RegisterMiniMaxExecutionDrivers(executionDrivers, miniMaxTransport); errDrivers != nil {
		return fmt.Errorf("register MiniMax execution drivers: %w", errDrivers)
	}
	if errDrivers := bootstrap.RegisterTavilyExecutionDrivers(executionDrivers, openPlatformTransport); errDrivers != nil {
		return fmt.Errorf("register Tavily execution drivers: %w", errDrivers)
	}
	if errDrivers := bootstrap.RegisterDeepSeekExecutionDrivers(executionDrivers, openPlatformTransport); errDrivers != nil {
		return fmt.Errorf("register DeepSeek execution drivers: %w", errDrivers)
	}
	if errFactory := bootstrap.RegisterCustomExecutionDriverFactory(executionDrivers, openPlatformTransport); errFactory != nil {
		return fmt.Errorf("register custom compatibility execution factory: %w", errFactory)
	}
	// runtimeFeedback applies classified execution outcomes using copied bounded cooldown behavior.
	// runtimeFeedback 使用复制的有界冷却行为应用分类执行结果。
	runtimeFeedback, errRuntimeFeedback := runtimefeedback.NewController(routingStates)
	if errRuntimeFeedback != nil {
		return fmt.Errorf("create runtime feedback controller: %w", errRuntimeFeedback)
	}
	// executions owns the durable public execution lifecycle and exact provider dispatch.
	// executions 拥有持久化公共执行生命周期与精确供应商分派。
	executions, errExecutions := executioncore.NewService(executionStore, targetResolver, configurations, inputPlans, inputMaterializer, executionDrivers, executioncore.ServiceOptions{Retention: 24 * time.Hour, OutputResources: resourceGateway, RuntimeFeedback: runtimeFeedback, Leases: executionStore, LeaseTTL: 30 * time.Second, ModelTools: routerToolResolver})
	if errExecutions != nil {
		return fmt.Errorf("create execution service: %w", errExecutions)
	}
	// accessController enforces local tenant/project isolation and exposes interfaces replaceable by shared services.
	// accessController 强制执行本地租户/项目隔离，并暴露可由共享服务替换的接口。
	accessController, errAccessController := access.NewLocalController(access.Limits{RequestsPerMinute: 600, ConcurrentRequests: 64, AuditEntries: 10000})
	if errAccessController != nil {
		return fmt.Errorf("create access controller: %w", errAccessController)
	}
	// callIdentityVerifier is absent by default and accepts only one explicitly configured OIDC trust boundary.
	// callIdentityVerifier 默认不存在，并且仅接受一个显式配置的 OIDC 信任边界。
	var callIdentityVerifier access.IdentityVerifier
	if oidcConfiguration := controlConfiguration.OIDCConfiguration(); oidcConfiguration != nil && oidcConfiguration.Enabled {
		oidcVerifier, errOIDCVerifier := access.NewOIDCVerifier(access.OIDCVerifierConfig{Issuer: oidcConfiguration.Issuer, Audience: oidcConfiguration.Audience, JWKSURL: oidcConfiguration.JWKSURL})
		if errOIDCVerifier != nil {
			return fmt.Errorf("create call-plane OIDC verifier: %w", errOIDCVerifier)
		}
		callIdentityVerifier = oidcVerifier
	}
	// api exposes separated authenticated Vulcan management and call-plane routes.
	// api 暴露相互隔离且经认证的 Vulcan 管理面和调用面路由。
	api, errAPI := httpapi.NewWithControlPlane(executionDrivers, httpapi.ControlPlane{
		Query:                     managementQueries,
		Commands:                  managementCommands,
		ModelAccess:               modelAccessCommands,
		CustomCatalogs:            customCatalogCommands,
		MetadataRefresh:           metadataRefreshCoordinator,
		Routing:                   routingManagement,
		RouterTools:               routerToolBindings,
		ModelToolAvailability:     routerToolResolver,
		Protocols:                 protocols,
		APIKeys:                   controlConfiguration,
		Auth:                      controlConfiguration,
		Access:                    accessController,
		CallIdentityVerifier:      callIdentityVerifier,
		AccessDiagnostics:         accessController,
		Resources:                 resourceGateway,
		InputPlans:                inputPlans,
		Executions:                executions,
		Preflight:                 executions,
		ResourceDiagnostics:       resourceService,
		ExecutionDiagnostics:      executions,
		CatalogChanges:            catalogs,
		ProviderFileDiagnostics:   miniMaxFileUploader,
		Targets:                   targetResolver,
		CredentialRefreshRecovery: runtimeFeedback,
		KimiDeviceFlows:           kimiDeviceFlows,
		KimiTokens:                kimiTokens,
		MiniMaxDeviceFlows:        miniMaxDeviceFlows,
		MiniMaxTokens:             miniMaxTokens,
		XAIDeviceFlows:            xaiDeviceFlows,
		XAITokens:                 xaiTokens,
		CodexDeviceFlows:          codexDeviceFlows,
		CodexOAuthFlows:           codexOAuthFlows,
		CodexTokens:               codexTokens,
		ClaudeOAuthFlows:          claudeOAuthFlows,
		ClaudeTokens:              claudeTokens,
		AntigravityOAuthFlows:     antigravityOAuthFlows,
		AntigravityTokens:         antigravityTokens,
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
	server := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	// serveErrors receives the terminal serve result exactly once.
	// serveErrors 只接收一次最终服务结果。
	serveErrors := make(chan error, 1)
	// recoveryErrors receives a terminal durable task-recovery failure without logging task affinity.
	// recoveryErrors 接收持久化任务恢复终止错误且不记录任务亲和性。
	recoveryErrors := make(chan error, 1)
	// metadataRefreshErrors receives the terminal background metadata coordinator result.
	// metadataRefreshErrors 接收后台元数据协调器的终止结果。
	metadataRefreshErrors := make(chan error, 1)
	go func() {
		if options.tlsCertificatePath != "" {
			serveErrors <- server.ServeTLS(listener, options.tlsCertificatePath, options.tlsPrivateKeyPath)
			return
		}
		serveErrors <- server.Serve(listener)
	}()
	go func() {
		recoveryErrors <- executions.RunRecovery(ctx, time.Second)
	}()
	go func() {
		metadataRefreshErrors <- metadataRefreshCoordinator.Run(ctx)
	}()
	log.Printf("vulcan-model-core listening on %s", listener.Addr())

	select {
	case errServe := <-serveErrors:
		if errServe != nil && !errors.Is(errServe, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP API: %w", errServe)
		}
		return nil
	case errRecovery := <-recoveryErrors:
		if errRecovery != nil && !errors.Is(errRecovery, context.Canceled) {
			return fmt.Errorf("run durable execution recovery: %w", errRecovery)
		}
		return nil
	case errMetadataRefreshRun := <-metadataRefreshErrors:
		if errMetadataRefreshRun != nil && !errors.Is(errMetadataRefreshRun, context.Canceled) {
			return fmt.Errorf("run provider metadata refresh coordinator: %w", errMetadataRefreshRun)
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
