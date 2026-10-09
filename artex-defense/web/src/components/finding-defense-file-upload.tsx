"use client";

import * as React from "react";

import { UploadIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { type DefenseExecution, type DefenseFileConfig, securityApi } from "@/lib/security-api";

const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
type LoadedFile = { name: string; content: string; bytes: number };

function localDateTime(timestamp: number) {
  if (!Number.isFinite(timestamp)) return "";
  const date = new Date(timestamp);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
}

function defaultStart(execution: DefenseExecution) {
  const date = new Date(execution.retest.started_at ?? execution.retest.created_at);
  return localDateTime(Math.floor(date.getTime() / 1000) * 1000 - 30000);
}

function defaultEnd(execution: DefenseExecution) {
  if (!execution.retest.finished_at) return "";
  // Round outward even when Date loses a sub-millisecond database fraction.
  return localDateTime(Math.floor(new Date(execution.retest.finished_at).getTime() / 1000) * 1000 + 61000);
}

export function FindingDefenseFileUpload({
  findingId,
  execution,
  disabled,
  readOnly,
  onRunningChange,
  onUploaded,
}: {
  findingId: string;
  execution: DefenseExecution;
  disabled: boolean;
  readOnly: boolean;
  onRunningChange: (running: boolean) => void;
  onUploaded: () => Promise<void>;
}) {
  const t = useTranslations("purple.upload");
  const fieldId = React.useId();
  const [auditFile, setAuditFile] = React.useState<LoadedFile | null>(null);
  const [alertFile, setAlertFile] = React.useState<LoadedFile | null>(null);
  const [noAlerts, setNoAlerts] = React.useState(false);
  const [coverageStart, setCoverageStart] = React.useState(() => defaultStart(execution));
  const [coverageEnd, setCoverageEnd] = React.useState(() => defaultEnd(execution));
  const [coverageComplete, setCoverageComplete] = React.useState(false);
  const [reading, setReading] = React.useState(false);
  const [uploading, setUploading] = React.useState(false);
  const [error, setError] = React.useState("");
  const config = execution.source_snapshot.config as DefenseFileConfig;
  const totalBytes = (auditFile?.bytes ?? 0) + (alertFile?.bytes ?? 0);

  const readFile = async (file: File | undefined, kind: "audit" | "alert") => {
    if (!file) return;
    setError("");
    const otherBytes = kind === "audit" ? (alertFile?.bytes ?? 0) : (auditFile?.bytes ?? 0);
    if (file.size + otherBytes > MAX_UPLOAD_BYTES) {
      setError(t("tooLarge"));
      return;
    }
    setReading(true);
    try {
      // Preserve BOM and line endings for the server's original-file hash.
      const content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer());
      const loaded = { name: file.name, content, bytes: file.size };
      if (kind === "audit") setAuditFile(loaded);
      else setAlertFile(loaded);
      setCoverageComplete(false);
    } catch {
      setError(t("fileError"));
    } finally {
      setReading(false);
    }
  };

  const upload = async () => {
    if (!auditFile || disabled || readOnly || reading || uploading || (noAlerts && alertFile)) return;
    const start = new Date(coverageStart);
    const end = new Date(coverageEnd);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start) {
      setError(t("invalidPeriod"));
      return;
    }
    if (end.getTime() > Date.now()) {
      setError(t("futurePeriod"));
      return;
    }
    if (totalBytes > MAX_UPLOAD_BYTES) {
      setError(t("tooLarge"));
      return;
    }
    setUploading(true);
    onRunningChange(true);
    setError("");
    try {
      await securityApi.upload(findingId, execution.id, {
        audit_file: { name: auditFile.name, content: auditFile.content },
        ...(alertFile ? { alert_file: { name: alertFile.name, content: alertFile.content } } : {}),
        no_alerts: noAlerts,
        coverage_start: start.toISOString(),
        coverage_end: end.toISOString(),
        coverage_complete: coverageComplete,
      });
      await onUploaded();
      toast.success(t("saved"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setUploading(false);
      onRunningChange(false);
    }
  };

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-violet-500/30 p-4">
      <h4 className="font-medium">{t("title")}</h4>
      <p className="text-sm text-muted-foreground">{t("description")}</p>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <details>
        <summary className="cursor-pointer text-sm">{t("mappingSnapshot")}</summary>
        <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
          {(["timestamp_field", "correlation_field", "action_field", "event_id_field"] as const).map((key) => (
            <React.Fragment key={key}>
              <dt className="text-muted-foreground">{t(key)}</dt>
              <dd className="break-all font-mono">{config[key]}</dd>
            </React.Fragment>
          ))}
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">{t("correlationHelp", { id: execution.correlation_id })}</p>
      </details>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void upload();
        }}
      >
        <fieldset className="flex flex-col gap-4" disabled={disabled || readOnly || reading || uploading}>
          <div className="grid gap-4 sm:grid-cols-2">
            {(["audit", "alert"] as const).map((kind) => {
              const file = kind === "audit" ? auditFile : alertFile;
              return (
                <div key={kind} className="flex min-w-0 flex-col gap-2">
                  <Label htmlFor={`${fieldId}-${kind}`}>{t(`${kind}File`)}</Label>
                  <Input
                    id={`${fieldId}-${kind}`}
                    type="file"
                    accept=".json,.jsonl,.ndjson,.csv"
                    disabled={kind === "alert" && noAlerts}
                    onChange={(event) => {
                      const selectedFile = event.target.files?.[0];
                      event.target.value = "";
                      void readFile(selectedFile, kind);
                    }}
                  />
                  <p className="text-xs text-muted-foreground">{t(`${kind}Help`)}</p>
                  {file ? (
                    <div className="flex items-center justify-between gap-2 rounded-md bg-muted p-2">
                      <span className="min-w-0 break-all text-xs">
                        {file.name} · {(file.bytes / 1024).toFixed(1)} KiB
                      </span>
                      <Button
                        type="button"
                        size="icon-sm"
                        variant="ghost"
                        aria-label={t("removeFile", { name: file.name })}
                        onClick={() => {
                          if (kind === "audit") setAuditFile(null);
                          else setAlertFile(null);
                          setCoverageComplete(false);
                        }}
                      >
                        <XIcon />
                      </Button>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
          <div className="flex items-start gap-2">
            <input
              id={`${fieldId}-no-alerts`}
              type="checkbox"
              className="mt-0.5"
              checked={noAlerts}
              disabled={alertFile !== null}
              onChange={(event) => {
                setNoAlerts(event.target.checked);
                setCoverageComplete(false);
              }}
            />
            <Label htmlFor={`${fieldId}-no-alerts`} className="leading-relaxed">
              {t("noAlerts")}
            </Label>
          </div>
          {!alertFile && !noAlerts ? (
            <p className="text-xs text-amber-700 dark:text-amber-300">{t("missingAlert")}</p>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-2">
              <Label htmlFor={`${fieldId}-from`}>{t("coverageStart")}</Label>
              <Input
                id={`${fieldId}-from`}
                type="datetime-local"
                step="1"
                required
                value={coverageStart}
                onChange={(event) => {
                  setCoverageStart(event.target.value);
                  setCoverageComplete(false);
                }}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor={`${fieldId}-to`}>{t("coverageEnd")}</Label>
              <Input
                id={`${fieldId}-to`}
                type="datetime-local"
                step="1"
                required
                value={coverageEnd}
                onChange={(event) => {
                  setCoverageEnd(event.target.value);
                  setCoverageComplete(false);
                }}
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{t("periodHelp")}</p>
          <div className="flex items-start gap-2">
            <input
              id={`${fieldId}-complete`}
              type="checkbox"
              className="mt-0.5"
              checked={coverageComplete}
              onChange={(event) => setCoverageComplete(event.target.checked)}
            />
            <Label htmlFor={`${fieldId}-complete`} className="leading-relaxed">
              {t("coverageComplete")}
            </Label>
          </div>
          <p className="text-xs text-muted-foreground">{t("attestation")}</p>
          <p className="text-xs text-muted-foreground">{t("limits", { n: (totalBytes / 1024).toFixed(1) })}</p>
          <p className="text-xs text-muted-foreground">{t("privacy")}</p>
          <Button type="submit" className="self-start" disabled={!auditFile || totalBytes > MAX_UPLOAD_BYTES}>
            {uploading || reading ? <Spinner /> : <UploadIcon />}
            {t("submit")}
          </Button>
        </fieldset>
      </form>
    </div>
  );
}
