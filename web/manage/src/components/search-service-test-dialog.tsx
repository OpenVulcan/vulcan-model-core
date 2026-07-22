import { type FormEvent, useEffect, useState } from "react";
import { X } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useI18n } from "@/i18n";
import {
  testSearchService,
  type SearchServiceTestResult,
} from "@/lib/model-capabilities";

// SearchServiceTestTarget contains the exact provider-owned service selection and declared policy used by one test.
// SearchServiceTestTarget 包含一次测试使用的精确供应商所属服务选择及声明策略。
export interface SearchServiceTestTarget {
  // providerInstanceID fixes the configured provider instance.
  // providerInstanceID 固定已配置供应商实例。
  providerInstanceID: string;
  // providerName is the safe management-facing instance name.
  // providerName 是管理界面安全显示的实例名称。
  providerName: string;
  // providerServiceID fixes the logical search service.
  // providerServiceID 固定逻辑搜索服务。
  providerServiceID: string;
  // serviceName is the safe management-facing service name.
  // serviceName 是管理界面安全显示的服务名称。
  serviceName: string;
  // serviceOfferingID fixes one concrete search implementation.
  // serviceOfferingID 固定一个具体搜索实现。
  serviceOfferingID: string;
  // executionProfileID fixes one executable typed search profile.
  // executionProfileID 固定一个可执行类型化搜索规格。
  executionProfileID: string;
  // outputMode is the first code-owned mode declared by this exact profile.
  // outputMode 是此精确规格声明的首个代码拥有输出模式。
  outputMode: string;
  // evidenceRequirement is the first code-owned policy declared by this exact profile.
  // evidenceRequirement 是此精确规格声明的首个代码拥有证据策略。
  evidenceRequirement: string;
}

// SearchServiceTestDialogProps defines one reusable provider-backed search diagnostic dialog.
// SearchServiceTestDialogProps 定义一个可复用的供应商支持搜索诊断对话框。
interface SearchServiceTestDialogProps {
  // managementAuthToken authorizes the protected diagnostic execution.
  // managementAuthToken 授权受保护的诊断执行。
  managementAuthToken: string;
  // target opens the dialog for one exact search profile; null closes it.
  // target 为一个精确搜索规格打开对话框；null 关闭对话框。
  target: SearchServiceTestTarget | null;
  // onClose clears the target owned by the calling page.
  // onClose 清除调用页面拥有的目标。
  onClose: () => void;
}

// SearchServiceTestDialog executes and renders one real unified provider search diagnostic.
// SearchServiceTestDialog 执行并渲染一次真实的统一供应商搜索诊断。
export function SearchServiceTestDialog({
  managementAuthToken,
  target,
  onClose,
}: SearchServiceTestDialogProps) {
  const { t } = useI18n();
  // searchQuery contains the current operator-entered diagnostic text.
  // searchQuery 包含当前操作员输入的诊断文本。
  const [searchQuery, setSearchQuery] = useState("");
  // searchResult contains only a strictly validated provider result.
  // searchResult 仅包含经过严格校验的供应商结果。
  const [searchResult, setSearchResult] =
    useState<SearchServiceTestResult | null>(null);
  // searchPending reports one active provider execution.
  // searchPending 表示一次正在执行的供应商调用。
  const [searchPending, setSearchPending] = useState(false);
  // searchError contains a safe management-facing failure message.
  // searchError 包含管理界面可安全显示的失败消息。
  const [searchError, setSearchError] = useState("");

  useEffect(() => {
    setSearchQuery("");
    setSearchResult(null);
    setSearchError("");
  }, [target]);

  // closeSearchTest prevents closing while the explicit provider request is still active.
  // closeSearchTest 在显式供应商请求仍在执行时阻止关闭。
  function closeSearchTest(): void {
    if (!searchPending) onClose();
  }

  // submitSearchTest sends one explicit real query through the selected typed service profile.
  // submitSearchTest 通过所选类型化服务规格发送一次显式真实查询。
  async function submitSearchTest(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!target || searchQuery.trim() === "") return;
    setSearchPending(true);
    setSearchError("");
    setSearchResult(null);
    try {
      setSearchResult(
        await testSearchService(managementAuthToken, {
          providerInstanceID: target.providerInstanceID,
          providerServiceID: target.providerServiceID,
          serviceOfferingID: target.serviceOfferingID,
          executionProfileID: target.executionProfileID,
          query: searchQuery.trim(),
          outputMode: target.outputMode,
          evidenceRequirement: target.evidenceRequirement,
        }),
      );
    } catch (error: unknown) {
      setSearchError(
        error instanceof Error && error.message
          ? error.message
          : t("services.searchFailed"),
      );
    } finally {
      setSearchPending(false);
    }
  }

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) closeSearchTest();
      }}
    >
      <DialogContent className="overflow-hidden sm:max-w-2xl">
        <DialogHeader>
          <div className="grid gap-1 pr-10">
            <DialogTitle>{t("services.searchTestTitle")}</DialogTitle>
            <DialogDescription>
              {t("services.searchTestDescription")}
            </DialogDescription>
          </div>
        </DialogHeader>
        <Button
          aria-label={t("services.closeTest")}
          className="text-destructive hover:bg-destructive/10 hover:text-destructive absolute top-4 right-4"
          disabled={searchPending}
          size="icon-sm"
          type="button"
          variant="ghost"
          onClick={closeSearchTest}
        >
          <X />
        </Button>
        <form
          className="grid shrink-0 gap-2"
          onSubmit={(event) => void submitSearchTest(event)}
        >
          <div className="flex items-center gap-2">
            <Label className="sr-only" htmlFor="service-search-test-query">
              {t("services.searchQuery")}
            </Label>
            <Input
              autoFocus
              className="min-w-0 flex-1"
              id="service-search-test-query"
              maxLength={8192}
              placeholder={t("services.searchQueryPlaceholder")}
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
            />
            <Button
              className="shrink-0"
              disabled={searchPending || searchQuery.trim() === ""}
              type="submit"
            >
              {searchPending
                ? t("services.searching")
                : t("services.searchTest")}
            </Button>
          </div>
          {searchError ? (
            <p className="text-destructive text-sm" role="alert">
              {searchError}
            </p>
          ) : null}
        </form>
        {searchResult ? <SearchTestResults result={searchResult} /> : null}
      </DialogContent>
    </Dialog>
  );
}

// SearchTestResultsProps contains one validated provider-backed search response.
// SearchTestResultsProps 包含一个经过校验的供应商支持搜索响应。
interface SearchTestResultsProps {
  // result is the complete unified search response.
  // result 是完整的统一搜索响应。
  result: SearchServiceTestResult;
}

// SearchTestResults renders essential search evidence inside an independently scrolling result region.
// SearchTestResults 在独立滚动的结果区域内渲染必要搜索证据。
function SearchTestResults({ result }: SearchTestResultsProps) {
  const { t } = useI18n();
  // hasDisplayableResult reports whether the provider returned any user-visible search evidence.
  // hasDisplayableResult 表示供应商是否返回任何用户可见搜索证据。
  const hasDisplayableResult = Boolean(
    result.search.answer ||
    result.search.results.length ||
    result.search.citations.length ||
    result.search.sources.length,
  );
  return (
    <section
      className="grid max-h-[min(55vh,420px)] min-h-0 gap-3 overflow-y-auto border-t pr-1 pt-4"
      aria-label={t("services.searchResults")}
    >
      <h3 className="font-semibold">{t("services.searchResults")}</h3>
      {result.search.answer ? (
        <div className="grid gap-1">
          <h4 className="text-sm font-medium">{t("services.searchAnswer")}</h4>
          <p className="whitespace-pre-wrap text-sm">{result.search.answer}</p>
        </div>
      ) : null}
      {result.search.results.length ? (
        <ol className="grid gap-3">
          {result.search.results.map((item) => (
            <li className="rounded-lg border p-3" key={item.id}>
              <div className="flex items-start gap-2">
                <span className="text-muted-foreground text-xs tabular-nums">
                  {item.rank}
                </span>
                <div className="min-w-0">
                  <a
                    className="font-medium underline-offset-4 hover:underline"
                    href={item.url}
                    rel="noreferrer"
                    target="_blank"
                  >
                    {item.title || item.url}
                  </a>
                  {item.source_domain ? (
                    <p className="text-muted-foreground text-xs">
                      {item.source_domain}
                    </p>
                  ) : null}
                  {item.snippet ? (
                    <p className="mt-1 line-clamp-2 text-sm">
                      {searchSnippetText(item.snippet)}
                    </p>
                  ) : null}
                </div>
              </div>
            </li>
          ))}
        </ol>
      ) : null}
      {result.search.citations.length ? (
        <div className="grid gap-2">
          <h4 className="text-sm font-medium">
            {t("services.searchCitations")}
          </h4>
          <ul className="grid gap-1 text-sm">
            {result.search.citations.map((citation) => (
              <li key={citation.id}>
                <a
                  className="underline-offset-4 hover:underline"
                  href={citation.url}
                  rel="noreferrer"
                  target="_blank"
                >
                  {citation.title || citation.url}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {result.search.sources.length ? (
        <div className="grid gap-2">
          <h4 className="text-sm font-medium">{t("services.searchSources")}</h4>
          <ul className="grid gap-1 text-sm">
            {result.search.sources.map((source, index) => (
              <li key={`${source.type}:${source.url}:${index}`}>
                <a
                  className="underline-offset-4 hover:underline"
                  href={source.url}
                  rel="noreferrer"
                  target="_blank"
                >
                  {source.url}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {!hasDisplayableResult ? (
        <p className="text-muted-foreground text-sm">
          {t("services.searchNoResults")}
        </p>
      ) : null}
    </section>
  );
}

// searchSnippetText converts provider HTML fragments into compact plain text without executing markup.
// searchSnippetText 将供应商 HTML 片段转换为紧凑纯文本且不执行标记。
export function searchSnippetText(value: string): string {
  const parsed = new DOMParser().parseFromString(value, "text/html");
  return (parsed.body.textContent ?? "").replace(/\s+/g, " ").trim();
}
