"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowLeftIcon, CableIcon, PencilIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { HttpError } from "@/lib/api";
import { type SecuritySource, type SecuritySourceConfig, securityApi } from "@/lib/security-api";

const DEFAULT_CONFIG: SecuritySourceConfig = {
  base_url: "",
  index: "main",
  audit_sourcetype: "artex:audit",
  alert_sourcetype: "artex:alert",
  correlation_field: "artex_verification_id",
  action_field: "action",
  tls_fingerprint: "",
};
const CONFIG_FIELDS = [
  "index",
  "audit_sourcetype",
  "alert_sourcetype",
  "correlation_field",
  "action_field",
  "tls_fingerprint",
] as const;

export default function PurpleSourcesPage() {
  const t = useTranslations("purple.sources");
  const tp = useTranslations("purple");
  const fieldId = React.useId();
  const [sources, setSources] = React.useState<SecuritySource[] | null>(null);
  const [editing, setEditing] = React.useState<SecuritySource | null>(null);
  const [name, setName] = React.useState("");
  const [config, setConfig] = React.useState<SecuritySourceConfig>({ ...DEFAULT_CONFIG });
  const [enabled, setEnabled] = React.useState(true);
  const [authMode, setAuthMode] = React.useState<"keep" | "token" | "basic">("token");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [token, setToken] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [loadError, setLoadError] = React.useState("");
  const [testResult, setTestResult] = React.useState<{ id: string; detail: string } | null>(null);
  const seq = React.useRef(0);

  const load = React.useCallback(async () => {
    const request = ++seq.current;
    setLoading(true);
    setLoadError("");
    try {
      const result = await securityApi.sources();
      if (request === seq.current) setSources(result.sources ?? []);
    } catch (e) {
      if (request === seq.current) setLoadError((e as Error).message);
    } finally {
      if (request === seq.current) setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
    return () => {
      seq.current++;
    };
  }, [load]);

  const edit = (source: SecuritySource | null) => {
    setEditing(source);
    setName(source?.name ?? "");
    setConfig(source ? { ...source.config } : { ...DEFAULT_CONFIG });
    setEnabled(source?.enabled ?? true);
    setAuthMode(source?.credential_set ? "keep" : "token");
    setUsername("");
    setPassword("");
    setToken("");
    setError("");
  };

  const save = async () => {
    if (busy) return;
    if ((authMode === "token" && !token.trim()) || (authMode === "basic" && (!username.trim() || !password))) {
      setError(t("credentialsRequired"));
      return;
    }
    setBusy("save");
    setError("");
    try {
      let credentials: { token?: string; username?: string; password?: string } = {};
      if (authMode === "token") credentials = { token: token.trim() };
      else if (authMode === "basic") credentials = { username: username.trim(), password };
      await securityApi.saveSource(editing?.id ?? null, {
        name: name.trim(),
        config,
        enabled,
        expected_revision: editing?.revision ?? 0,
        ...credentials,
      });
      edit(null);
      setTestResult(null);
      await load();
      toast.success(t("saved"));
    } catch (e) {
      if (e instanceof HttpError && e.status === 409) {
        await load();
        setError(t("conflict"));
      } else setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const test = async (source: SecuritySource) => {
    if (busy) return;
    setBusy(source.id);
    setError("");
    setTestResult(null);
    try {
      const result = await securityApi.testSource(source.id);
      if (result.ok) setTestResult({ id: source.id, detail: result.detail });
      else setError(result.detail);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-1 flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b px-4 py-3 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Button asChild variant="ghost" size="sm">
          <Link href="/function/purple">
            <ArrowLeftIcon />
            {tp("title")}
          </Link>
        </Button>
        <CableIcon className="size-5 text-violet-500" />
        <h1 className="font-semibold">{t("title")}</h1>
      </header>
      <div className="flex flex-col gap-5 p-4 lg:p-6">
        <p className="max-w-3xl text-sm text-muted-foreground">{t("description")}</p>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        <div className="grid items-start gap-5 xl:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>{editing ? t("editTitle", { name: editing.name }) : t("createTitle")}</CardTitle>
              <CardDescription>{t("formDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void save();
                }}
              >
                <fieldset className="flex flex-col gap-4" disabled={!!busy}>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-name`}>{t("name")}</Label>
                    <Input
                      id={`${fieldId}-name`}
                      required
                      maxLength={120}
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-url`}>{t("base_url")}</Label>
                    <Input
                      id={`${fieldId}-url`}
                      type="url"
                      pattern="https://.+"
                      placeholder="https://splunk.example.com:8089"
                      required
                      maxLength={2048}
                      value={config.base_url}
                      onChange={(event) => setConfig({ ...config, base_url: event.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">{t("urlHelp")}</p>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    {CONFIG_FIELDS.map((key) => (
                      <div key={key} className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-${key}`}>{t(key)}</Label>
                        <Input
                          id={`${fieldId}-${key}`}
                          required={key !== "tls_fingerprint"}
                          maxLength={128}
                          value={config[key]}
                          onChange={(event) => setConfig({ ...config, [key]: event.target.value })}
                        />
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">{t("fingerprintHelp")}</p>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-auth`}>{t("authentication")}</Label>
                    <select
                      id={`${fieldId}-auth`}
                      className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                      value={authMode}
                      onChange={(event) => {
                        setAuthMode(event.target.value as "keep" | "token" | "basic");
                        setUsername("");
                        setPassword("");
                        setToken("");
                      }}
                    >
                      {editing?.credential_set ? <option value="keep">{t("auth.keep")}</option> : null}
                      <option value="token">{t("auth.token")}</option>
                      <option value="basic">{t("auth.basic")}</option>
                    </select>
                  </div>
                  {authMode === "token" ? (
                    <div className="flex flex-col gap-2">
                      <Label htmlFor={`${fieldId}-token`}>{t("token")}</Label>
                      <Input
                        id={`${fieldId}-token`}
                        type="password"
                        autoComplete="new-password"
                        required
                        maxLength={8192}
                        value={token}
                        onChange={(event) => setToken(event.target.value)}
                      />
                    </div>
                  ) : null}
                  {authMode === "basic" ? (
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-username`}>{t("username")}</Label>
                        <Input
                          id={`${fieldId}-username`}
                          autoComplete="off"
                          required
                          maxLength={256}
                          value={username}
                          onChange={(event) => setUsername(event.target.value)}
                        />
                      </div>
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-password`}>{t("password")}</Label>
                        <Input
                          id={`${fieldId}-password`}
                          type="password"
                          autoComplete="new-password"
                          required
                          maxLength={8192}
                          value={password}
                          onChange={(event) => setPassword(event.target.value)}
                        />
                      </div>
                    </div>
                  ) : null}
                  <p className="text-xs text-muted-foreground">{t("credentialsHelp")}</p>
                  <div className="flex items-center gap-2">
                    <input
                      id={`${fieldId}-enabled`}
                      type="checkbox"
                      checked={enabled}
                      onChange={(event) => setEnabled(event.target.checked)}
                    />
                    <Label htmlFor={`${fieldId}-enabled`}>{t("enabled")}</Label>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button type="submit" disabled={!name.trim() || !config.base_url.trim()}>
                      {busy === "save" ? <Spinner /> : null}
                      {t("save")}
                    </Button>
                    <Button type="button" variant="ghost" onClick={() => edit(null)}>
                      {editing ? t("cancelEdit") : t("clear")}
                    </Button>
                  </div>
                </fieldset>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <CardTitle>{t("listTitle")}</CardTitle>
              <Button variant="ghost" size="sm" disabled={loading || !!busy} onClick={() => void load()}>
                <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
                {tp("refresh")}
              </Button>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {loadError ? (
                <Alert variant="destructive">
                  <AlertDescription>{loadError}</AlertDescription>
                </Alert>
              ) : null}
              {sources === null && loading ? <Skeleton className="h-24" /> : null}
              {sources?.length === 0 ? <p className="text-sm text-muted-foreground">{t("empty")}</p> : null}
              {sources?.map((source) => (
                <div key={source.id} className="rounded-lg border p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="font-medium">{source.name}</p>
                      <p className="mt-1 break-all text-xs text-muted-foreground">{source.config.base_url}</p>
                    </div>
                    <Badge variant="outline">{source.enabled ? t("active") : t("disabled")}</Badge>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {t("revision", { n: source.revision })} ·{" "}
                    {source.credential_set ? t("credentialsSet") : t("credentialsMissing")}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {source.config.index} · {source.config.audit_sourcetype} / {source.config.alert_sourcetype}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" disabled={!!busy} onClick={() => edit(source)}>
                      <PencilIcon />
                      {t("edit")}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!!busy || !source.credential_set}
                      onClick={() => void test(source)}
                    >
                      {busy === source.id ? <Spinner /> : <CableIcon />}
                      {t("test")}
                    </Button>
                  </div>
                  {testResult?.id === source.id ? (
                    <p className="mt-3 text-sm text-teal-700 dark:text-teal-300">{testResult.detail}</p>
                  ) : null}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
