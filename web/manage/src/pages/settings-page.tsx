import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { ReadonlyCombobox } from "@/components/ui/readonly-combobox";
import { useI18n } from "@/i18n";
import {
  fetchRoutingSettings,
  updateRoutingSettings,
  type RoutingSettings,
} from "@/lib/provider-groups";

// SettingsPageProps contains the in-memory credential used only for authenticated management requests.
// SettingsPageProps 包含仅用于认证管理请求的内存凭据。
interface SettingsPageProps {
  // managementAuthToken authorizes the local management API.
  // managementAuthToken 授权本地管理 API。
  managementAuthToken: string;
}

// SettingsPage renders persisted global account scheduling policy.
// SettingsPage 渲染持久化全局账号调度策略。
export function SettingsPage({ managementAuthToken }: SettingsPageProps) {
  const { t } = useI18n();
  const [settings, setSettings] = useState<RoutingSettings | null>(null);
  const [strategy, setStrategy] = useState<"round_robin" | "fill_first">(
    "round_robin",
  );
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(false);
    void fetchRoutingSettings(managementAuthToken, controller.signal)
      .then((loaded) => {
        setSettings(loaded);
        setStrategy(loaded.strategy);
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(true);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [managementAuthToken]);

  // saveStrategy persists the selected strategy and replaces the local revision with the server result.
  // saveStrategy 持久化所选策略并使用服务端结果替换本地修订号。
  async function saveStrategy() {
    setSaving(true);
    setError(false);
    try {
      const updated = await updateRoutingSettings(
        managementAuthToken,
        strategy,
      );
      setSettings(updated);
    } catch {
      setError(true);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="px-4 lg:px-6">
      <Card className="max-w-3xl">
        <CardHeader>
          <CardTitle>{t("settings.accountRouting")}</CardTitle>
          <CardDescription>{t("settings.accountRoutingHelp")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="default-routing-strategy">
              {t("settings.defaultStrategy")}
            </Label>
            <ReadonlyCombobox
              value={strategy}
              disabled={loading || saving}
              onValueChange={(value) => {
                if (value === "round_robin" || value === "fill_first") {
                  setStrategy(value);
                }
              }}
              options={[
                { value: "round_robin", label: t("settings.roundRobin") },
                { value: "fill_first", label: t("settings.fillFirst") },
              ]}
              id="default-routing-strategy"
              className="w-full"
            />
          </div>
          <p className="text-muted-foreground text-sm">
            {strategy === "round_robin"
              ? t("settings.roundRobinHelp")
              : t("settings.fillFirstHelp")}
          </p>
          <p className="text-muted-foreground text-xs">
            {t("settings.ineligibleSkipped")}
          </p>
          {settings ? (
            <p className="text-muted-foreground text-xs">
              {t("settings.revision")}: {settings.revision}
            </p>
          ) : null}
          {error ? (
            <p className="text-destructive text-sm" role="alert">
              {t("settings.saveFailed")}
            </p>
          ) : null}
          <Button
            type="button"
            disabled={loading || saving || settings?.strategy === strategy}
            onClick={saveStrategy}
          >
            {saving ? t("settings.saving") : t("settings.save")}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
