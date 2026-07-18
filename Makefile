# This Makefile owns the repeatable local development lifecycle on Windows.
# 此 Makefile 管理 Windows 上可重复的本地开发生命周期。

.DEFAULT_GOAL := help

# PROJECT_ROOT is the repository directory from which Make was invoked.
# PROJECT_ROOT 是执行 Make 时所在的仓库目录。
PROJECT_ROOT := $(abspath .)
# OUTPUT_ROOT is the ignored build and startup-artifact root.
# OUTPUT_ROOT 是被忽略的构建产物与启动信息根目录。
OUTPUT_ROOT := $(PROJECT_ROOT)/output
# BIN_DIRECTORY holds the compiled core executable.
# BIN_DIRECTORY 保存编译后的核心可执行文件。
BIN_DIRECTORY := $(OUTPUT_ROOT)/bin
# CONFIG_DIRECTORY holds the process startup YAML configuration.
# CONFIG_DIRECTORY 保存进程启动 YAML 配置。
CONFIG_DIRECTORY := $(OUTPUT_ROOT)/configs
# CONFIGURATION_FILE is the active local control-plane configuration file.
# CONFIGURATION_FILE 是生效中的本地控制面配置文件。
CONFIGURATION_FILE := $(CONFIG_DIRECTORY)/vulcan-model-core.yaml
# CONFIGURATION_TEMPLATE is the tracked bootstrap configuration template.
# CONFIGURATION_TEMPLATE 是受版本控制的引导配置模板。
CONFIGURATION_TEMPLATE := $(PROJECT_ROOT)/vulcan-model-core.example.yaml
# POWERSHELL is the Windows host used for process lifecycle helpers.
# POWERSHELL 是用于进程生命周期辅助操作的 Windows 主机。
POWERSHELL ?= powershell
# RUN_CORE_SCRIPT starts the compiled executable with the prescribed runtime paths.
# RUN_CORE_SCRIPT 使用规定的运行时路径启动编译后的可执行文件。
RUN_CORE_SCRIPT := $(PROJECT_ROOT)/scripts/run-core.ps1
# VITE_SCRIPT starts and stops only the Vite process it records.
# VITE_SCRIPT 仅启动和停止其记录的 Vite 进程。
VITE_SCRIPT := $(PROJECT_ROOT)/scripts/vite.ps1
# CONFIG_SCRIPT materializes the ignored startup configuration without overwriting it.
# CONFIG_SCRIPT 生成被忽略的启动配置且不会覆盖已有文件。
CONFIG_SCRIPT := $(PROJECT_ROOT)/scripts/create-runtime-config.ps1

# CORE_BINARY_NAME follows the executable suffix expected by the current host.
# CORE_BINARY_NAME 使用当前主机所需的可执行文件后缀。
CORE_BINARY_NAME := vulcan-model-core
ifeq ($(OS),Windows_NT)
CORE_BINARY_NAME := vulcan-model-core.exe
endif
# CORE_BINARY is rebuilt by every make run invocation.
# CORE_BINARY 会在每次执行 make run 时重新构建。
CORE_BINARY := $(BIN_DIRECTORY)/$(CORE_BINARY_NAME)

# VITE_OPERATION maps the requested make vite start|stop command form to one action.
# VITE_OPERATION 将请求的 make vite start|stop 命令形式映射为一个动作。
VITE_OPERATION := start
ifneq ($(filter vite,$(MAKECMDGOALS)),)
ifneq ($(filter stop,$(MAKECMDGOALS)),)
VITE_OPERATION := stop
endif
endif

.PHONY: help config run vite vite-start vite-stop start stop

# help prints the supported local development commands.
# help 打印支持的本地开发命令。
help:
	@echo "make config      Create output/configs/vulcan-model-core.yaml without overwriting it"
	@echo "make run         Build into output/bin and start the core from that directory"
	@echo "make vite start  Start the local management-page Vite server in the background"
	@echo "make vite stop   Stop only the Vite server recorded by Make"

# config creates the ignored startup configuration from the tracked template.
# config 从受版本控制的模板创建被忽略的启动配置。
config:
	@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File "$(CONFIG_SCRIPT)" -TemplatePath "$(CONFIGURATION_TEMPLATE)" -ConfigurationPath "$(CONFIGURATION_FILE)"

# run rebuilds the core executable and starts it from output/bin on every invocation.
# run 每次执行都会重新构建核心可执行文件并从 output/bin 启动它。
run:
	@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -Command "New-Item -ItemType Directory -Force -Path '$(BIN_DIRECTORY)' | Out-Null"
	go build -o "$(CORE_BINARY)" ./cmd/vulcan-model-core
	@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File "$(RUN_CORE_SCRIPT)" -BinaryPath "$(CORE_BINARY)" -RelativeConfigurationPath "../configs/vulcan-model-core.yaml"

# vite dispatches the documented make vite start|stop command form.
# vite 分派文档中约定的 make vite start|stop 命令形式。
vite:
	@$(MAKE) --no-print-directory vite-$(VITE_OPERATION)

# vite-start starts Vite as a hidden, recorded background process.
# vite-start 将 Vite 作为隐藏且已记录的后台进程启动。
vite-start:
	@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File "$(VITE_SCRIPT)" -Action Start -ProjectRoot "$(PROJECT_ROOT)"

# vite-stop stops only the Vite process represented by the recorded state.
# vite-stop 只停止由已记录状态表示的 Vite 进程。
vite-stop:
	@$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -File "$(VITE_SCRIPT)" -Action Stop -ProjectRoot "$(PROJECT_ROOT)"

# start and stop are standalone aliases unless they accompany the vite command form.
# start 和 stop 在未与 vite 命令形式组合时作为独立别名。
ifneq ($(filter vite,$(MAKECMDGOALS)),)
start stop:
	@:
else
start: vite-start
stop: vite-stop
endif
