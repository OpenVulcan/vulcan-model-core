import { useEffect, useState } from "react";
import { ChevronRight, X } from "lucide-react";

import {
  ExtractServiceTestDialog,
  type ExtractServiceTestTarget,
} from "@/components/extract-service-test-dialog";
import {
  SearchServiceTestDialog,
  type SearchServiceTestTarget,
} from "@/components/search-service-test-dialog";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useI18n } from "@/i18n";

// ServiceTestOption binds one exact diagnostic target to its current executable readiness.
// ServiceTestOption 将一个精确诊断目标绑定到其当前可执行就绪状态。
export interface ServiceTestOption<TTarget> {
  // target contains the immutable provider service selection.
  // target 包含不可变的供应商服务选择。
  target: TTarget;
  // ready reports whether a configured credential can execute this diagnostic now.
  // ready 表示已配置凭据当前是否能够执行此诊断。
  ready: boolean;
}

// ServiceTestTarget contains every diagnostic supported by one configured provider.
// ServiceTestTarget 包含一个已配置供应商支持的全部诊断。
export interface ServiceTestTarget {
  // providerName is the management-facing provider name.
  // providerName 是管理界面显示的供应商名称。
  providerName: string;
  // search selects the provider's preferred typed search profile when available.
  // search 在可用时选择供应商首选的类型化搜索规格。
  search?: ServiceTestOption<SearchServiceTestTarget>;
  // extract selects the provider's preferred typed extraction profile when available.
  // extract 在可用时选择供应商首选的类型化提取规格。
  extract?: ServiceTestOption<ExtractServiceTestTarget>;
}

// ServiceTestDialogProps defines the unified management diagnostic entry point.
// ServiceTestDialogProps 定义统一的管理诊断入口。
interface ServiceTestDialogProps {
  // managementAuthToken authorizes real provider-backed diagnostic requests.
  // managementAuthToken 授权真实的供应商诊断请求。
  managementAuthToken: string;
  // target contains the provider and its available diagnostic kinds.
  // target 包含供应商及其可用诊断类型。
  target: ServiceTestTarget | null;
  // onClose releases the complete unified diagnostic flow.
  // onClose 释放完整的统一诊断流程。
  onClose: () => void;
}

// ServiceTestKind identifies the selected child diagnostic inside the unified flow.
// ServiceTestKind 标识统一流程内选择的子诊断。
type ServiceTestKind = "search" | "extract" | null;

// ServiceTestDialog lets the operator choose Search or Extract before entering the exact typed test.
// ServiceTestDialog 允许操作员在进入精确类型化测试前选择搜索或提取。
export function ServiceTestDialog({
  managementAuthToken,
  target,
  onClose,
}: ServiceTestDialogProps) {
  const { t } = useI18n();
  // selectedKind keeps both diagnostics behind one stable Test action.
  // selectedKind 将两种诊断统一置于一个稳定的“测试”操作之后。
  const [selectedKind, setSelectedKind] = useState<ServiceTestKind>(null);

  useEffect(() => {
    setSelectedKind(null);
  }, [target]);

  if (selectedKind === "search" && target?.search) {
    return (
      <SearchServiceTestDialog
        managementAuthToken={managementAuthToken}
        target={target.search.target}
        onClose={() => setSelectedKind(null)}
      />
    );
  }
  if (selectedKind === "extract" && target?.extract) {
    return (
      <ExtractServiceTestDialog
        managementAuthToken={managementAuthToken}
        target={target.extract.target}
        onClose={() => setSelectedKind(null)}
      />
    );
  }

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <div className="grid gap-1 pr-10">
            <DialogTitle>{t("services.testTitle")}</DialogTitle>
            <DialogDescription>
              {t("services.testDescription")} {target?.providerName}
            </DialogDescription>
          </div>
        </DialogHeader>
        <Button
          aria-label={t("services.closeTest")}
          className="text-destructive hover:bg-destructive/10 hover:text-destructive absolute top-4 right-4"
          size="icon-sm"
          type="button"
          variant="ghost"
          onClick={onClose}
        >
          <X />
        </Button>
        <div className="grid gap-2">
          {target?.search ? (
            <Button
              className="h-12 w-full justify-between px-4 text-left"
              disabled={!target.search.ready}
              type="button"
              variant="outline"
              onClick={() => setSelectedKind("search")}
            >
              <span className="flex min-w-0 items-center gap-3">
                <span className="font-medium">{t("services.search")}</span>
                <span className="text-muted-foreground truncate text-sm font-normal">
                  {target.search.target.serviceName}
                </span>
              </span>
              <ChevronRight className="text-muted-foreground size-4 shrink-0" />
            </Button>
          ) : null}
          {target?.extract ? (
            <Button
              className="h-12 w-full justify-between px-4 text-left"
              disabled={!target.extract.ready}
              type="button"
              variant="outline"
              onClick={() => setSelectedKind("extract")}
            >
              <span className="flex min-w-0 items-center gap-3">
                <span className="font-medium">{t("services.extract")}</span>
                <span className="text-muted-foreground truncate text-sm font-normal">
                  {target.extract.target.serviceName}
                </span>
              </span>
              <ChevronRight className="text-muted-foreground size-4 shrink-0" />
            </Button>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
