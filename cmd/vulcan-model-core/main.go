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

	"github.com/OpenVulcan/vulcan-model-core/internal/core"
	"github.com/OpenVulcan/vulcan-model-core/internal/httpapi"
	"github.com/OpenVulcan/vulcan-model-core/internal/management"
	"github.com/OpenVulcan/vulcan-model-core/internal/providerconfig"
	"github.com/OpenVulcan/vulcan-model-core/internal/sqlitestore"
)

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

// run parses configuration and serves the minimal HTTP API until cancellation.
// run 解析配置并提供最小 HTTP API，直到收到取消信号。
func run(ctx context.Context, args []string) error {
	// flags owns command line parsing without global mutable flag state.
	// flags 独立管理命令行解析，避免使用全局可变标志状态。
	flags := flag.NewFlagSet("vulcan-model-core", flag.ContinueOnError)
	// listenAddress receives the loopback listener address and defaults to a random port.
	// listenAddress 接收环回监听地址并默认使用随机端口。
	listenAddress := flags.String("listen-address", "127.0.0.1:0", "HTTP listen address")
	// databasePath receives the durable SQLite configuration and catalog path.
	// databasePath 接收持久化 SQLite 配置与目录路径。
	databasePath := flags.String("database-path", "vulcan-model-core.db", "SQLite configuration and catalog path")
	if errParse := flags.Parse(args); errParse != nil {
		return fmt.Errorf("parse command flags: %w", errParse)
	}

	// protocols owns shared upstream protocol metadata registered by future adapters.
	// protocols 管理由未来 Adapter 注册的共享上游协议元数据。
	protocols := providerconfig.NewProtocolRegistry()
	// systemDefinitions owns immutable code-registered provider definitions.
	// systemDefinitions 管理代码注册的不可变系统供应商定义。
	systemDefinitions, errSystemDefinitions := providerconfig.NewSystemRegistry(protocols)
	if errSystemDefinitions != nil {
		return fmt.Errorf("create system provider registry: %w", errSystemDefinitions)
	}
	// database owns durable non-secret configuration and atomic catalog snapshots.
	// database 管理持久化非秘密配置与原子目录快照。
	database, errDatabase := sqlitestore.Open(ctx, *databasePath)
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
	// registry begins empty until explicit provider adapters are added.
	// registry 在显式添加供应商适配器前保持为空。
	registry := core.NewRegistry()
	// api exposes framework and client-safe Vulcan management discovery endpoints.
	// api 暴露框架与客户端安全 Vulcan 管理发现端点。
	api, errAPI := httpapi.NewWithManagement(registry, managementQueries)
	if errAPI != nil {
		return fmt.Errorf("create HTTP API: %w", errAPI)
	}
	// listener binds before the process announces readiness information.
	// listener 在进程公布监听信息前完成绑定。
	listener, errListen := net.Listen("tcp", *listenAddress)
	if errListen != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddress, errListen)
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
