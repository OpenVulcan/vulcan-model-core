import { type FormEvent, useEffect, useMemo, useState } from "react";
import { X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ReadonlyCombobox } from "@/components/ui/readonly-combobox";
import { Textarea } from "@/components/ui/textarea";
import { useI18n } from "@/i18n";
import {
  testExtractService,
  type ExtractServiceTestResult,
} from "@/lib/model-capabilities";

// ExtractServiceTestTarget contains the exact provider-owned extraction service and declared limits.
// ExtractServiceTestTarget 包含精确的供应商所属内容提取服务及声明限制。
export interface ExtractServiceTestTarget {
  providerInstanceID: string;
  providerName: string;
  providerServiceID: string;
  serviceName: string;
  serviceOfferingID: string;
  executionProfileID: string;
  maxURLs: number;
  depths: Array<"basic" | "advanced">;
  formats: Array<"markdown" | "text">;
  queryRelevance: boolean;
  minimumChunksPerSource: number;
  maximumChunksPerSource: number;
  includeImages: boolean;
  includeFavicon: boolean;
  minimumTimeoutSeconds: number;
  maximumTimeoutSeconds: number;
}

// ExtractServiceTestDialogProps defines one reusable provider-backed extraction diagnostic dialog.
// ExtractServiceTestDialogProps 定义一个可复用的供应商支持内容提取诊断对话框。
interface ExtractServiceTestDialogProps {
  managementAuthToken: string;
  target: ExtractServiceTestTarget | null;
  onClose: () => void;
}

// ExtractServiceTestDialog executes and renders one real typed provider extraction diagnostic.
// ExtractServiceTestDialog 执行并渲染一次真实类型化供应商内容提取诊断。
export function ExtractServiceTestDialog({ managementAuthToken, target, onClose }: ExtractServiceTestDialogProps) {
  const { t } = useI18n();
  const [urlText, setURLText] = useState("");
  const [query, setQuery] = useState("");
  const [chunksPerSource, setChunksPerSource] = useState("3");
  const [depth, setDepth] = useState<"basic" | "advanced">("basic");
  const [format, setFormat] = useState<"markdown" | "text">("markdown");
  const [includeImages, setIncludeImages] = useState(false);
  const [includeFavicon, setIncludeFavicon] = useState(false);
  const [timeoutSeconds, setTimeoutSeconds] = useState("");
  const [result, setResult] = useState<ExtractServiceTestResult | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const urls = useMemo(() => urlText.split(/\r?\n/).map((value) => value.trim()).filter(Boolean), [urlText]);

  useEffect(() => {
    setURLText("");
    setQuery("");
    setChunksPerSource("3");
    setDepth(target?.depths[0] ?? "basic");
    setFormat(target?.formats[0] ?? "markdown");
    setIncludeImages(false);
    setIncludeFavicon(false);
    setTimeoutSeconds("");
    setResult(null);
    setError("");
  }, [target]);

  // closeExtractTest prevents closing while an explicit provider request is active.
  // closeExtractTest 在显式供应商请求仍在执行时阻止关闭。
  function closeExtractTest(): void {
    if (!pending) onClose();
  }

  // submitExtractTest sends one bounded real extraction through the selected typed profile.
  // submitExtractTest 通过所选类型化规格发送一次有界真实内容提取。
  async function submitExtractTest(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!target || urls.length === 0 || urls.length > target.maxURLs) return;
    setPending(true);
    setError("");
    setResult(null);
    try {
      const parsedChunks = query.trim() ? Number(chunksPerSource) : undefined;
      const parsedTimeout = timeoutSeconds === "" ? undefined : Number(timeoutSeconds);
      setResult(await testExtractService(managementAuthToken, {
        providerInstanceID: target.providerInstanceID,
        providerServiceID: target.providerServiceID,
        serviceOfferingID: target.serviceOfferingID,
        executionProfileID: target.executionProfileID,
        urls,
        query: query.trim(),
        chunksPerSource: parsedChunks,
        depth,
        format,
        includeImages,
        includeFavicon,
        timeoutSeconds: parsedTimeout,
      }));
    } catch (caught: unknown) {
      setError(caught instanceof Error && caught.message ? caught.message : t("services.extractFailed"));
    } finally {
      setPending(false);
    }
  }

  const validURLCount = Boolean(target && urls.length > 0 && urls.length <= target.maxURLs);
  return (
    <Dialog open={target !== null} onOpenChange={(open) => { if (!open) closeExtractTest(); }}>
      <DialogContent className="max-h-[min(80vh,600px)] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <div className="grid gap-1 pr-10">
            <DialogTitle>{t("services.extractTestTitle")}</DialogTitle>
            <DialogDescription>{t("services.extractTestDescription")}</DialogDescription>
          </div>
        </DialogHeader>
        <Button
          aria-label={t("services.closeTest")}
          className="text-destructive hover:bg-destructive/10 hover:text-destructive absolute top-4 right-4"
          disabled={pending}
          size="icon-sm"
          type="button"
          variant="ghost"
          onClick={closeExtractTest}
        >
          <X />
        </Button>
        <form className="grid gap-4" onSubmit={(event) => void submitExtractTest(event)}>
          <div className="grid gap-2">
            <Label htmlFor="service-extract-test-urls">{t("services.extractURLs")}</Label>
            <Textarea autoFocus id="service-extract-test-urls" placeholder={t("services.extractURLsPlaceholder")} value={urlText} onChange={(event) => setURLText(event.target.value)} />
            <p className="text-muted-foreground text-xs">{t("services.extractURLLimit")}: {target?.maxURLs ?? 0} · {target?.providerName} · {target?.serviceName}</p>
          </div>
          {target?.queryRelevance ? (
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_10rem]">
              <div className="grid gap-2">
                <Label htmlFor="service-extract-test-query">{t("services.extractQuery")}</Label>
                <Input id="service-extract-test-query" value={query} onChange={(event) => setQuery(event.target.value)} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="service-extract-test-chunks">{t("services.extractChunks")}</Label>
                <Input disabled={query.trim() === ""} id="service-extract-test-chunks" max={target.maximumChunksPerSource} min={target.minimumChunksPerSource} type="number" value={chunksPerSource} onChange={(event) => setChunksPerSource(event.target.value)} />
              </div>
            </div>
          ) : null}
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="grid gap-2">
              <Label htmlFor="service-extract-test-depth">{t("services.extractDepth")}</Label>
              <ReadonlyCombobox id="service-extract-test-depth" value={depth} options={(target?.depths ?? []).map((value) => ({ value, label: value === "basic" ? t("services.extractDepthBasic") : t("services.extractDepthAdvanced") }))} onValueChange={(value) => setDepth(value as "basic" | "advanced")} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="service-extract-test-format">{t("services.extractFormat")}</Label>
              <ReadonlyCombobox id="service-extract-test-format" value={format} options={(target?.formats ?? []).map((value) => ({ value, label: value === "markdown" ? t("services.extractFormatMarkdown") : t("services.extractFormatText") }))} onValueChange={(value) => setFormat(value as "markdown" | "text")} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="service-extract-test-timeout">{t("services.extractTimeout")}</Label>
              <Input id="service-extract-test-timeout" min={target?.minimumTimeoutSeconds} max={target?.maximumTimeoutSeconds} placeholder={`${target?.minimumTimeoutSeconds ?? 1}–${target?.maximumTimeoutSeconds ?? 60}`} type="number" value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(event.target.value)} />
            </div>
          </div>
          <div className="flex flex-wrap gap-5">
            {target?.includeImages ? <label className="flex items-center gap-2 text-sm"><Checkbox checked={includeImages} onCheckedChange={setIncludeImages} />{t("services.extractIncludeImages")}</label> : null}
            {target?.includeFavicon ? <label className="flex items-center gap-2 text-sm"><Checkbox checked={includeFavicon} onCheckedChange={setIncludeFavicon} />{t("services.extractIncludeFavicon")}</label> : null}
          </div>
          <p className="text-muted-foreground text-xs">{t("services.extractConsumesQuota")}</p>
          {error ? <p className="text-destructive text-sm" role="alert">{error}</p> : null}
          <div className="flex justify-end gap-2">
            <Button disabled={pending || !validURLCount} type="submit">{pending ? t("services.extracting") : t("services.extractTest")}</Button>
          </div>
        </form>
        {result ? <ExtractTestResults result={result} /> : null}
      </DialogContent>
    </Dialog>
  );
}

// ExtractTestResults renders successful content, structured failures, and exact provider accounting.
// ExtractTestResults 渲染成功内容、结构化失败与精确供应商计量。
function ExtractTestResults({ result }: { result: ExtractServiceTestResult }) {
  const { t } = useI18n();
  return (
    <section className="grid gap-3 border-t pt-4" aria-label={t("services.extractResults")}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">{t("services.extractResults")}</h3>
        <Badge variant="outline">{result.extract.results.length} {t("services.extractSucceeded")}</Badge>
        {result.extract.failed_results.length ? <Badge variant="destructive">{result.extract.failed_results.length} {t("services.extractFailedCount")}</Badge> : null}
        {result.extract.response_time_seconds !== undefined ? <Badge variant="secondary">{result.extract.response_time_seconds}s</Badge> : null}
      </div>
      {result.extract.results.map((item) => (
        <article className="grid gap-2 rounded-lg border p-3" key={item.url}>
          <a className="truncate font-medium underline-offset-4 hover:underline" href={item.url} rel="noreferrer" target="_blank">{item.url}</a>
          <pre className="bg-muted max-h-64 overflow-auto whitespace-pre-wrap rounded-md p-3 text-xs">{item.raw_content}</pre>
          {item.images.length ? <div className="flex flex-wrap gap-2">{item.images.map((imageURL) => <a className="text-xs underline" href={imageURL} key={imageURL} rel="noreferrer" target="_blank">{imageURL}</a>)}</div> : null}
        </article>
      ))}
      {result.extract.failed_results.map((item) => <div className="border-destructive/40 rounded-lg border p-3 text-sm" key={item.url}><p className="font-medium">{item.url}</p><p className="text-destructive">{item.error}</p></div>)}
      {result.extract.provider_request_id ? <p className="text-muted-foreground text-xs">{t("services.providerRequestID")}: {result.extract.provider_request_id}</p> : null}
    </section>
  );
}
