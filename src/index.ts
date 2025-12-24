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

  /**
   * The "policyHash" MUST be computed over the corresponding PrivatePolicySpec
   * using RFC8785 canonicalization + sha256 (recommended).
   */
  integrity: {
    canonicalization: "RFC8785";
    policyHash: PolicyHash;
    /** Optional: pin the evaluator implementation */
    codeRef?: CodeRef;
  };
}
