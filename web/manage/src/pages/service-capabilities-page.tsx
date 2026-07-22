import { useEffect, useState } from "react";

import {
  ServiceTestDialog,
  type ServiceTestTarget,
} from "@/components/service-test-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useI18n } from "@/i18n";
import {
  fetchCapabilityCatalogs,
  type ProviderCapabilityCatalog,
} from "@/lib/model-capabilities";

// ServiceCapabilitiesPageProps defines the credential needed to read and test special-service contracts.
// ServiceCapabilitiesPageProps 定义读取及测试特殊服务合同所需的凭证。
interface ServiceCapabilitiesPageProps {
  // managementAuthToken authorizes management catalog reads and explicit diagnostic executions.
  // managementAuthToken 授权管理目录读取及显式诊断执行。
  managementAuthToken: string;
}

// ServiceCapabilitiesPage renders typed special services and executes provider-backed diagnostics without model discovery.
// ServiceCapabilitiesPage 渲染类型化特殊服务，并在不执行模型发现的情况下运行供应商诊断。
export function ServiceCapabilitiesPage({
  managementAuthToken,
}: ServiceCapabilitiesPageProps) {
  // catalogs contains independently validated service catalogs.
  // catalogs 包含独立校验后的服务目录。
  const [catalogs, setCatalogs] = useState<ProviderCapabilityCatalog[]>([]);
  // loading distinguishes the initial request from an empty service catalog.
  // loading 区分初始请求与空服务目录。
  const [loading, setLoading] = useState(true);
  // failed reports that the complete service view cannot be trusted.
  // failed 表示完整服务视图无法被信任。
  const [failed, setFailed] = useState(false);
  // serviceTestTarget contains every executable diagnostic for the selected provider.
  // serviceTestTarget 包含所选供应商的全部可执行诊断。
  const [serviceTestTarget, setServiceTestTarget] =
    useState<ServiceTestTarget | null>(null);
  const { t } = useI18n();

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setFailed(false);
    fetchCapabilityCatalogs(managementAuthToken, controller.signal)
      .then(setCatalogs)
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError")
          return;
        setFailed(true);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [managementAuthToken]);

  if (loading) {
    return (
      <div className="grid gap-4 px-4 lg:px-6">
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (failed) {
    return (
      <Card className="mx-4 lg:mx-6">
        <CardHeader>
          <CardTitle>{t("capabilities.loadFailed")}</CardTitle>
          <CardDescription>
            {t("capabilities.loadFailedDescription")}
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }
  if (catalogs.every(({ catalog }) => catalog.services.length === 0)) {
    return (
      <Card className="mx-4 lg:mx-6">
        <CardHeader>
          <CardTitle>{t("capabilities.noServices")}</CardTitle>
          <CardDescription>
            {t("capabilities.noServicesDescription")}
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <>
      <div className="grid gap-4 px-4 lg:px-6">
        {catalogs.flatMap(({ provider, catalog }) =>
          catalog.services.map((service) => (
            <Card key={`${provider.instance.id}:${service.id}`}>
              <CardHeader>
                <div className="flex flex-wrap items-center gap-2">
                  <CardTitle>{service.display_name}</CardTitle>
                  <Badge variant="outline">
                    {provider.instance.display_name}
                  </Badge>
                  <Badge variant="outline">{service.operation}</Badge>
                  <Badge variant={service.enabled ? "default" : "secondary"}>
                    {service.enabled
                      ? t("capabilities.enabled")
                      : t("capabilities.disabled")}
                  </Badge>
                  <Badge
                    variant={
                      service.authorization_status === "authorized"
                        ? "default"
                        : service.authorization_status === "denied"
                          ? "destructive"
                          : "secondary"
                    }
                  >
                    {service.authorization_status === "authorized"
                      ? t("capabilities.authorized")
                      : service.authorization_status === "denied"
                        ? t("capabilities.unauthorized")
                        : t("capabilities.unknown")}
                  </Badge>
                  <Button
                    className="ml-auto"
                    disabled={
                      !serviceTestTargetHasReadyCapability(
                        providerServiceTestTarget({ provider, catalog }),
                      )
                    }
                    size="sm"
                    type="button"
                    variant="outline"
                    onClick={() =>
                      setServiceTestTarget(
                        providerServiceTestTarget({ provider, catalog }),
                      )
                    }
                  >
                    {t("services.test")}
                  </Button>
                </div>
                <CardDescription>{service.id}</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-3">
                {service.offerings.flatMap((offering) =>
                  offering.profiles.map((profile) => {
                    const search = profile.capabilities.web_search;
                    const extract = profile.capabilities.web_extract;
                    return (
                      <section
                        key={profile.id}
                        className="grid gap-3 rounded-lg border p-4"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="font-semibold">
                            {profile.display_name}
                          </h3>
                          <Badge variant="secondary">
                            {t("capabilities.readyCredentials")}:{" "}
                            {profile.pool?.ready_credentials ?? 0}
                          </Badge>
                          {profile.pool &&
                          profile.pool.ready_credentials === 0 ? (
                            <Badge variant="destructive">
                              {t("capabilities.unavailable")}
                            </Badge>
                          ) : null}
                        </div>
                        {search ? (
                          <div className="grid gap-2 text-sm md:grid-cols-2">
                            <p>
                              <span className="font-medium">
                                {t("services.backendKind")}:
                              </span>{" "}
                              {search.backend_kind}
                            </p>
                            <p>
                              <span className="font-medium">
                                {t("services.invocationMode")}:
                              </span>{" "}
                              {search.invocation_mode}
                            </p>
                            <p>
                              <span className="font-medium">
                                {t("services.outputModes")}:
                              </span>{" "}
                              {search.output_modes.join(", ")}
                            </p>
                            <p>
                              <span className="font-medium">
                                {t("services.evidenceKinds")}:
                              </span>{" "}
                              {search.evidence_kinds.join(", ")}
                            </p>
                            <p className="md:col-span-2">
                              <span className="font-medium">
                                {t("services.evidenceRequirements")}:
                              </span>{" "}
                              {search.evidence_requirements.join(", ")}
                            </p>
                          </div>
                        ) : extract ? (
                          <div className="grid gap-2 text-sm md:grid-cols-2">
                            <p><span className="font-medium">{t("services.extractURLLimit")}:</span> {extract.max_urls}</p>
                            <p><span className="font-medium">{t("services.extractDepth")}:</span> {extract.depths.join(", ")}</p>
                            <p><span className="font-medium">{t("services.extractFormat")}:</span> {extract.formats.join(", ")}</p>
                            <p><span className="font-medium">{t("services.extractChunks")}:</span> {extract.minimum_chunks_per_source}–{extract.maximum_chunks_per_source}</p>
                          </div>
                        ) : (
                          <p className="text-muted-foreground text-sm">
                            {t("services.noTypedContract")}
                          </p>
                        )}
                        {profile.pool ? (
                          <p className="text-muted-foreground text-xs">
                            {t("capabilities.configured")}:{" "}
                            {profile.pool.configured_credentials} ·{" "}
                            {t("capabilities.entitled")}:{" "}
                            {profile.pool.entitled_credentials} ·{" "}
                            {t("capabilities.cooling")}:{" "}
                            {profile.pool.cooling_credentials} ·{" "}
                            {t("capabilities.exhausted")}:{" "}
                            {profile.pool.exhausted_credentials} ·{" "}
                            {t("capabilities.invalid")}:{" "}
                            {profile.pool.invalid_credentials} ·{" "}
                            {t("capabilities.blockedBy")}:{" "}
                            {profile.pool.blocking_allowance_kinds.join(", ") ||
                              t("capabilities.none")}
                          </p>
                        ) : null}
                      </section>
                    );
                  }),
                )}
              </CardContent>
            </Card>
          )),
        )}
      </div>
      <ServiceTestDialog
        managementAuthToken={managementAuthToken}
        target={serviceTestTarget}
        onClose={() => setServiceTestTarget(null)}
      />
    </>
  );
}

// providerServiceTestTarget selects one preferred Search and Extract diagnostic from an authoritative provider catalog.
// providerServiceTestTarget 从权威供应商目录中分别选择一个首选搜索与提取诊断。
function providerServiceTestTarget({
  provider,
  catalog,
}: ProviderCapabilityCatalog): ServiceTestTarget | null {
  // searchCandidates preserve catalog order and the exact readiness of every valid search profile.
  // searchCandidates 保留目录顺序及每个有效搜索规格的精确就绪状态。
  const searchCandidates: Array<NonNullable<ServiceTestTarget["search"]>> = [];
  // extractCandidates preserve catalog order and the exact readiness of every valid extraction profile.
  // extractCandidates 保留目录顺序及每个有效提取规格的精确就绪状态。
  const extractCandidates: Array<NonNullable<ServiceTestTarget["extract"]>> = [];

  for (const service of catalog.services) {
    for (const offering of service.offerings) {
      for (const profile of offering.profiles) {
        const search = profile.capabilities.web_search;
        if (
          service.operation === "search.web" &&
          profile.operation === "search.web" &&
          search &&
          search.output_modes.length > 0 &&
          search.evidence_requirements.length > 0
        ) {
          searchCandidates.push({
            target: {
              providerInstanceID: provider.instance.id,
              providerName: provider.instance.display_name,
              providerServiceID: service.id,
              serviceName: service.display_name,
              serviceOfferingID: offering.id,
              executionProfileID: profile.id,
              outputMode: search.output_modes[0],
              evidenceRequirement: search.evidence_requirements[0],
            },
            ready:
              service.enabled && (profile.pool?.ready_credentials ?? 0) > 0,
          });
        }

        const extract = profile.capabilities.web_extract;
        if (
          service.operation === "web.extract" &&
          profile.operation === "web.extract" &&
          extract &&
          extract.depths.length > 0 &&
          extract.formats.length > 0
        ) {
          extractCandidates.push({
            target: {
              providerInstanceID: provider.instance.id,
              providerName: provider.instance.display_name,
              providerServiceID: service.id,
              serviceName: service.display_name,
              serviceOfferingID: offering.id,
              executionProfileID: profile.id,
              maxURLs: extract.max_urls,
              depths: extract.depths,
              formats: extract.formats,
              queryRelevance: extract.query_relevance,
              minimumChunksPerSource: extract.minimum_chunks_per_source,
              maximumChunksPerSource: extract.maximum_chunks_per_source,
              includeImages: extract.include_images,
              includeFavicon: extract.include_favicon,
              minimumTimeoutSeconds: extract.minimum_timeout_seconds,
              maximumTimeoutSeconds: extract.maximum_timeout_seconds,
            },
            ready:
              service.enabled && (profile.pool?.ready_credentials ?? 0) > 0,
          });
        }
      }
    }
  }

  // search prefers an immediately executable profile while retaining unavailable capability visibility.
  // search 优先选择可立即执行的规格，同时保留不可用能力的可见性。
  const search =
    searchCandidates.find((candidate) => candidate.ready) ?? searchCandidates[0];
  // extract prefers an immediately executable profile while retaining unavailable capability visibility.
  // extract 优先选择可立即执行的规格，同时保留不可用能力的可见性。
  const extract =
    extractCandidates.find((candidate) => candidate.ready) ??
    extractCandidates[0];
  if (!search && !extract) return null;
  return {
    providerName: provider.instance.display_name,
    search,
    extract,
  };
}

// serviceTestTargetHasReadyCapability reports whether at least one child diagnostic can execute now.
// serviceTestTargetHasReadyCapability 表示至少一个子诊断当前是否可以执行。
function serviceTestTargetHasReadyCapability(
  target: ServiceTestTarget | null,
): boolean {
  return Boolean(target?.search?.ready || target?.extract?.ready);
}
