import type {
  ActionOutcome,
  AppendPerceptResponse,
  AuditAttribution,
  CapabilitiesResponse,
  CallerCredential,
  CreateRunRequest,
  CreateRunResponse,
  HealthResponse,
  LifecycleRequest,
  Percept,
  ReplayResponse,
  RunInspectResponse,
  RunId,
  StateHead,
  SubmitActionRequest,
  TickResponse,
  TraceExportResponse,
  TracePageResponse,
  TraceRecord,
  VersionResponse,
  WorkOrderEnvelope
} from "@splendor/types";

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface SplendorClientOptions {
  /** Runtime daemon base URL. Resident/non-dev callers use HTTPS; loopback HTTP is explicit local development only. */
  baseUrl: string;
  /** Caller bearer token. The client never silently falls back to anonymous calls. */
  token: string;
  /** Optional fetch implementation for tests or controlled runtimes. */
  fetch?: FetchLike;
  /** Daemon API version header. Defaults to the 0.02-dev compatibility line. */
  apiVersion?: string;
  /** Optional default audit attribution for mutating calls. */
  defaultAudit?: AuditAttribution;
  /**
   * Optional compatibility mirror serialized into daemon headers/request bodies.
   * It is never authentication proof; the daemon derives authority only from the
   * verified bearer token and requires any supplied mirror to match it exactly.
   */
  defaultCredential?: CallerCredential | null;
}

export interface AppendPerceptOptions {
  credential?: CallerCredential | null;
  audit?: AuditAttribution;
}

export interface ReadTracesOptions {
  /** Required by the daemon security boundary before raw trace data is exposed. */
  redactionPolicy: string;
  start?: number;
  end?: number;
  credential?: CallerCredential | null;
  audit?: AuditAttribution;
}

export interface RequestReplayOptions {
  credential?: CallerCredential | null;
  audit?: AuditAttribution;
}

export interface DaemonErrorPayload {
  code?: string;
  message?: string;
  details?: unknown;
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
}

export class SplendorClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly requestId?: string;
  readonly responseBody?: unknown;

  constructor(params: {
    status: number;
    code: string;
    message: string;
    details?: unknown;
    requestId?: string;
    responseBody?: unknown;
  }) {
    super(params.message);
    this.name = "SplendorClientError";
    this.status = params.status;
    this.code = params.code;
    this.details = params.details;
    this.requestId = params.requestId;
    this.responseBody = params.responseBody;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class SplendorClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly fetcher: FetchLike;
  private readonly apiVersion: string;
  private readonly defaultAudit?: AuditAttribution;
  private readonly defaultCredential?: CallerCredential | null;

  constructor(options: SplendorClientOptions) {
    if (!options.baseUrl.trim()) {
      throw new TypeError("SplendorClient requires a daemon baseUrl");
    }
    if (!options.token.trim()) {
      throw new TypeError("SplendorClient requires an authenticated caller token; unauthenticated fallback is not allowed");
    }
    let parsedBaseUrl: URL;
    try {
      parsedBaseUrl = new URL(options.baseUrl);
    } catch {
      throw new TypeError("SplendorClient bearer transport requires HTTPS or explicit loopback HTTP without URL credentials, query, or fragment");
    }
    const hostname = parsedBaseUrl.hostname.toLowerCase();
    const hasQueryOrFragment = parsedBaseUrl.href.includes("?") || parsedBaseUrl.href.includes("#");
    const loopbackHttp = parsedBaseUrl.protocol === "http:" && (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]"
    );
    if (
      (parsedBaseUrl.protocol !== "https:" && !loopbackHttp) ||
      parsedBaseUrl.username !== "" ||
      parsedBaseUrl.password !== "" ||
      hasQueryOrFragment
    ) {
      throw new TypeError("SplendorClient bearer transport requires HTTPS or explicit loopback HTTP without URL credentials, query, or fragment");
    }
    parsedBaseUrl.pathname = parsedBaseUrl.pathname.endsWith("/")
      ? parsedBaseUrl.pathname
      : `${parsedBaseUrl.pathname}/`;
    this.baseUrl = parsedBaseUrl.toString();
    this.token = options.token;
    this.fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetcher) {
      throw new TypeError("SplendorClient requires a fetch implementation in this runtime");
    }
    this.apiVersion = options.apiVersion ?? "0.02-dev";
    this.defaultAudit = options.defaultAudit;
    this.defaultCredential = options.defaultCredential;
  }

  async createRun(request: CreateRunRequest): Promise<CreateRunResponse> {
    this.requireCreateRunIdempotency(request);
    if (!request?.work_order) {
      throw new TypeError("createRun requires a signed, scoped work order envelope");
    }
    this.validateCreateRunWorkOrder(request.work_order);
    this.requireMutatingAuthority(request.credential, request.audit_attribution);
    return this.request<CreateRunResponse>("POST", "runs", {
      body: request
    });
  }

  private requireCreateRunIdempotency(request: CreateRunRequest): void {
    if (typeof request?.request_id !== "string" || !request.request_id.trim()) {
      throw new TypeError("createRun requires a non-blank request_id");
    }
    if (typeof request?.idempotency_key !== "string" || !request.idempotency_key.trim()) {
      throw new TypeError("createRun requires a non-blank idempotency_key");
    }
  }

  async inspectRun(runId: RunId): Promise<RunInspectResponse> {
    return this.request<RunInspectResponse>("GET", `runs/${encodeURIComponent(runId)}`);
  }

  async startRun(runId: RunId, request: LifecycleRequest): Promise<TickResponse> {
    return this.lifecycle<TickResponse>(runId, "start", request);
  }

  async pauseRun(runId: RunId, request: LifecycleRequest): Promise<RunInspectResponse> {
    return this.lifecycle<RunInspectResponse>(runId, "pause", request);
  }

  async resumeRun(runId: RunId, request: LifecycleRequest): Promise<TickResponse> {
    return this.lifecycle<TickResponse>(runId, "resume", request);
  }

  async stopRun(runId: RunId, request: LifecycleRequest): Promise<RunInspectResponse> {
    return this.lifecycle<RunInspectResponse>(runId, "stop", request);
  }

  async cancelRun(runId: RunId, request: LifecycleRequest): Promise<RunInspectResponse> {
    return this.lifecycle<RunInspectResponse>(runId, "cancel", request);
  }

  async appendPercept(
    runId: RunId,
    percept: Percept,
    options: AppendPerceptOptions = {}
  ): Promise<AppendPerceptResponse> {
    const audit = this.requireAudit(options.audit);
    const credential = this.requireCredential(options.credential);
    return this.request<AppendPerceptResponse>("POST", `runs/${encodeURIComponent(runId)}/percepts`, {
      body: {
        credential,
        audit_attribution: audit,
        percept,
      }
    });
  }

  async readTracePage(runId: RunId, options: ReadTracesOptions): Promise<TracePageResponse> {
    if (!options?.redactionPolicy.trim()) {
      throw new TypeError("readTraces requires an explicit redactionPolicy");
    }
    return this.request<TracePageResponse>("GET", `runs/${encodeURIComponent(runId)}/traces`, {
      query: {
        redaction_policy: options.redactionPolicy,
        start: options.start,
        end: options.end
      }
    });
  }

  async exportTraces(runId: RunId, options: ReadTracesOptions): Promise<TraceExportResponse> {
    if (!options?.redactionPolicy.trim()) {
      throw new TypeError("exportTraces requires an explicit redactionPolicy");
    }
    return this.request<TraceExportResponse>("POST", `runs/${encodeURIComponent(runId)}/traces/export`, {
      body: {
        credential: this.requireCredential(options.credential),
        audit_attribution: this.requireAudit(options.audit),
        redaction_policy: options.redactionPolicy,
        start: options.start ?? null,
        end: options.end ?? null
      }
    });
  }

  async readTraces(runId: RunId, options: ReadTracesOptions): Promise<TraceRecord[]> {
    return (await this.readTracePage(runId, options)).records;
  }

  async *streamTraces(runId: RunId, options: ReadTracesOptions): AsyncIterable<TraceRecord> {
    for (const record of await this.readTraces(runId, options)) {
      yield record;
    }
  }

  async getStateHead(runId: RunId): Promise<StateHead> {
    return this.request<StateHead>("GET", `runs/${encodeURIComponent(runId)}/state-head`);
  }

  async requestReplay(runId: RunId, options: RequestReplayOptions = {}): Promise<ReplayResponse> {
    return this.request<ReplayResponse>("POST", `runs/${encodeURIComponent(runId)}/replay`, {
      body: {
        credential: this.requireCredential(options.credential),
        audit_attribution: this.requireAudit(options.audit),
        mode: "inspect_only",
        side_effects_allowed: false
      }
    });
  }

  async submitAction(request: SubmitActionRequest): Promise<ActionOutcome> {
    if (!request.causal_trace_id) {
      throw new TypeError("submitAction requires causal_trace_id trace linkage");
    }
    return this.request<ActionOutcome>("POST", "actions", {
      body: {
        ...request,
        credential: this.requireCredential(request.credential),
        audit_attribution: request.audit_attribution ?? this.requireAudit()
      }
    });
  }

  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "health");
  }

  async getVersion(): Promise<VersionResponse> {
    return this.request<VersionResponse>("GET", "version");
  }

  async getCapabilities(): Promise<CapabilitiesResponse> {
    return this.request<CapabilitiesResponse>("GET", "capabilities");
  }

  private lifecycle<T>(runId: RunId, action: "start" | "pause" | "resume" | "stop" | "cancel", request: LifecycleRequest): Promise<T> {
    return this.request<T>("POST", `runs/${encodeURIComponent(runId)}/${action}`, {
      body: {
        ...request,
        credential: this.requireCredential(request.credential),
        audit_attribution: request.audit_attribution ?? this.requireAudit()
      }
    });
  }

  private requireCredential(credential?: CallerCredential | null): CallerCredential {
    const resolved = credential ?? this.defaultCredential;
    if (!resolved) {
      throw new TypeError("mutating daemon calls require caller credential; unauthenticated fallback is not allowed");
    }
    return resolved;
  }

  private requireMutatingAuthority(credential?: CallerCredential | null, audit?: AuditAttribution | null): void {
    this.requireCredential(credential);
    if (!audit) {
      throw new TypeError("mutating daemon calls require audit attribution");
    }
  }

  private requireAudit(audit?: AuditAttribution): AuditAttribution {
    const attribution = audit ?? this.defaultAudit;
    if (!attribution) {
      throw new TypeError("mutating daemon calls require audit attribution");
    }
    return attribution;
  }

  private validateCreateRunWorkOrder(workOrder: WorkOrderEnvelope): void {
    if (!workOrder.signature?.key_id.trim() || !workOrder.signature.signature.trim()) {
      throw new TypeError("createRun requires signed work order signature metadata");
    }
    if (!workOrder.schema_version.trim() || !workOrder.work_order_id.trim() || !workOrder.objective.trim()) {
      throw new TypeError("createRun work order must include schema_version, work_order_id, and objective");
    }
    if (!workOrder.allowed_actions.length || !workOrder.allowed_adapters.length) {
      throw new TypeError("createRun work order must scope allowed actions and adapters");
    }
    if (!workOrder.placement?.target?.trim()) {
      throw new TypeError("createRun work order must include a placement target");
    }
    if (workOrder.revocation !== "active") {
      throw new TypeError("createRun work order must not be revoked");
    }
    const expiresAt = Date.parse(workOrder.expires_at);
    if (Number.isNaN(expiresAt) || expiresAt <= Date.now()) {
      throw new TypeError("createRun work order must have a future expires_at timestamp");
    }
  }

  private buildUrl(path: string, query?: Record<string, string | number | boolean | undefined>): URL {
    const url = new URL(path, this.baseUrl);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
    }
    return url;
  }

  private async request<T>(
    method: string,
    path: string,
    options: { body?: unknown; query?: Record<string, string | number | boolean | undefined> } = {}
  ): Promise<T> {
    const url = this.buildUrl(path, options.query);
    const headers = new Headers({
      Accept: "application/json",
      Authorization: `Bearer ${this.token}`,
      "X-Splendor-API-Version": this.apiVersion,
      "X-Splendor-Client": "@splendor/client"
    });
    if (this.defaultCredential) {
      headers.set("X-Splendor-Caller-Credential", JSON.stringify(this.defaultCredential));
    }
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
    }

    let response: Response;
    try {
      response = await this.fetcher(url, { method, headers, body, redirect: "error" });
    } catch (error) {
      const cause = this.redactText(error instanceof Error ? error.message : String(error));
      throw new SplendorClientError({
        status: 0,
        code: "network_error",
        message: "Daemon request failed before a response was received",
        details: { cause }
      });
    }

    if (!response.ok) {
      throw await this.toClientError(response);
    }

    if (response.status === 204) {
      return undefined as T;
    }
    const text = await response.text();
    if (!text.trim()) {
      return undefined as T;
    }
    try {
      return JSON.parse(text) as T;
    } catch (error) {
      throw new SplendorClientError({
        status: response.status,
        code: "invalid_json",
        message: "Daemon returned a non-JSON response",
        details: {
          cause: this.redactText(error instanceof Error ? error.message : String(error)),
          body: this.redactText(text)
        },
        requestId: this.redactOptionalText(response.headers.get("x-request-id") ?? response.headers.get("x-correlation-id")),
        responseBody: this.redactText(text)
      });
    }
  }

  private async toClientError(response: Response): Promise<SplendorClientError> {
    const requestId = this.redactOptionalText(response.headers.get("x-request-id") ?? response.headers.get("x-correlation-id"));
    const text = await response.text();
    let payload: DaemonErrorPayload | string = text;
    if (text.trim()) {
      try {
        payload = JSON.parse(text) as DaemonErrorPayload;
      } catch {
        payload = text;
      }
    }

    if (typeof payload === "object" && payload !== null) {
      const redactedPayload = this.redactUnknown(payload) as DaemonErrorPayload;
      const nested = redactedPayload.error;
      const code = nested?.code ?? redactedPayload.code ?? `http_${response.status}`;
      const message = nested?.message ?? redactedPayload.message ?? response.statusText;
      const details = nested?.details ?? redactedPayload.details ?? redactedPayload;
      return new SplendorClientError({
        status: response.status,
        code,
        message: this.redactText(message),
        details,
        requestId,
        responseBody: redactedPayload
      });
    }

    const redactedPayload = this.redactText(payload);
    return new SplendorClientError({
      status: response.status,
      code: `http_${response.status}`,
      message: this.redactText(response.statusText || "Daemon request failed"),
      details: { body: redactedPayload },
      requestId,
      responseBody: redactedPayload
    });
  }

  private redactText(value: string): string {
    return value.split(this.token).join("[REDACTED]");
  }

  private redactOptionalText(value: string | null): string | undefined {
    return value === null ? undefined : this.redactText(value);
  }

  private redactUnknown(value: unknown): unknown {
    if (typeof value === "string") {
      return this.redactText(value);
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.redactUnknown(item));
    }
    if (typeof value === "object" && value !== null) {
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, this.redactUnknown(item)])
      );
    }
    return value;
  }
}
