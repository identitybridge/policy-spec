/** RFC 8785 (JCS) canonical JSON bytes hashed -> policyHash */
export type PolicyHash = `sha256:${string}`;
export type PolicyId = string;
export type SemVer = `${number}.${number}.${number}`;
export type ISODateTime = string;

export type Duration =
  | `${number}ms`
  | `${number}s`
  | `${number}m`
  | `${number}h`
  | `${number}d`
  | `${number}w`;

export type Unit =
  | "count"
  | "ratio"
  | "percent"
  | "seconds"
  | "meters"
  | "kilometers"
  | "miles"
  | "celsius"
  | "fahrenheit"
  | "kwh"
  | "usd";

/** High-level provenance pointer */
export type CodeRef =
  | { type: "git"; repo: string; commit: string }
  | { type: "oci"; image: string; digest: string };

/** Publishable metadata */
export interface PolicyMetadata {
  title: string;
  description?: string;
  namespace: string;
  authors?: string[];
  createdAt?: ISODateTime;
  updatedAt?: ISODateTime;
  tags?: string[];
  references?: Array<{ label: string; url: string }>;
}

export interface SubjectSpec {
  type: "vehicle" | "device" | "portfolio" | "shipment" | "user" | string;
  idFormat?: "string" | "uuid" | "did" | "vin" | "tokenId" | string;
}

/** What a verifier is allowed to learn */
export interface DisclosureSpec {
  exposeClaims: string[];
  exposeRuleResults?: boolean;
  exposeInputs?: boolean;
}

/** Validity / refresh expectations */
export interface ValiditySpec {
  ttl: Duration;
  maxAge?: Duration;
  reusable?: boolean;
}

export interface OutputClaimSpec {
  name: string;
  type: "boolean" | "enum" | "number" | "string";
  unit?: Unit;

  derive:
    | { kind: "PASS_FAIL" }
    | { kind: "SCORE" }
    | {
        kind: "BAND";
        from: "SCORE";
        bands: Array<{
          label: string;
          minInclusive: number;
          maxExclusive: number;
        }>;
      }
    | { kind: "CONST"; value: string | number | boolean };
}

/**
 * PublicPolicySpec:
 * - What the claim means
 * - What gets disclosed
 * - How long it is valid
 * - How to identify the exact policy proven in ZK (policyHash)
 */
export interface PublicPolicySpec {
  id: PolicyId;
  version: SemVer;
  metadata: PolicyMetadata;
  subject: SubjectSpec;

  outputs: OutputClaimSpec[];
  validity: ValiditySpec;
  disclosure: DisclosureSpec;

  integrity: {
    canonicalization: "RFC8785";
    policyHash: PolicyHash;
    codeRef?: CodeRef;
  };
}

/**
 * Data sources are intentionally extensible.
 * Keep this JSON-serializable; avoid secrets here (store refs/hashes instead).
 */
export type DataSourceRef = {
  kind: string; // e.g. "http", "snowflake"
  ref?: string;
  config?: Record<string, unknown>;
};

export type AggregationSpec =
  | { op: "latest" }
  | { op: "min" | "max" | "avg" | "sum" }
  | { op: "count" }
  | { op: "p50" | "p90" | "p95" | "p99" }
  | { op: "distinctCount" }
  | { op: "windowedRate"; per: Duration };

export type InputValueType = "number" | "string" | "boolean";

export type TimeWindowSpec =
  | { mode: "point"; at: ISODateTime }
  | { mode: "range"; start: ISODateTime; end: ISODateTime }
  | { mode: "relative"; lookback: Duration; endOffset?: Duration };

/**
 * Policy input = "a scalar feature after applying time window + aggregation".
 * Keyed by `id` (also used by Expr refs and featuresHash inputsUsed map).
 */
export interface InputSpec {
  id: string;
  source: DataSourceRef;
  signal: string;
  valueType: InputValueType;
  unit?: Unit;
  time: TimeWindowSpec;
  aggregation: AggregationSpec; // recommended required
}
