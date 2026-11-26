/** Stable error codes emitted by urlguard. */
export type UrlGuardErrorCode =
  | 'INVALID_URL'
  | 'UNSAFE_SCHEME'
  | 'USERINFO_FORBIDDEN'
  | 'PRIVATE_IP'
  | 'DNS_REBIND'
  | 'HOST_DENIED'
  | 'HOST_NOT_ALLOWED'
  | 'PORT_FORBIDDEN'
  | 'TOO_MANY_HOPS'
  | 'REDIRECT_LOOP'
  | 'INPUT_TOO_LARGE'
  | 'UNSUPPORTED_IDNA'
  | 'RESOLUTION_FAILED';

/** Structured error with a stable code, human-readable reason and redacted input. */
export declare class UrlGuardError extends Error {
  readonly name: 'UrlGuardError';
  readonly code: UrlGuardErrorCode;
  readonly reason: string;
  readonly input: string;
  constructor(code: UrlGuardErrorCode, reason: string, input: unknown);
  toJSON(): { name: string; code: UrlGuardErrorCode; reason: string; input: string };
}

export declare function guardError(code: UrlGuardErrorCode, reason: string, input: unknown): UrlGuardError;

export interface DnsResolver {
  (hostname: string): Promise<readonly (string | { address: string; family?: number })[]>;
}

export interface HostPolicy {
  readonly allow?: readonly string[];
  readonly deny?: readonly string[];
  readonly allowPublicSuffix?: boolean;
}

export interface ValidateOptions {
  readonly allowedSchemes?: readonly string[];
  readonly allowUserinfo?: boolean;
  readonly allowedPorts?: readonly number[] | 'default-only' | 'any';
  readonly hostPolicy?: HostPolicy;
  readonly dns?: DnsResolver | false;
  readonly checkRebinding?: boolean;
  readonly rebindDelayMs?: number;
  readonly maxInputLength?: number;
  readonly idna?: 'ascii-only' | 'allow-unicode';
  readonly denyCidrs?: readonly string[];
  readonly allowCidrs?: readonly string[];
  readonly maxRedirects?: number;
}

export interface ValidationSuccess {
  readonly ok: true;
  readonly url: URL;
  readonly normalized: string;
  readonly hostname: string;
  /** Explicit or default port. Undefined for custom schemes with no port. */
  readonly port: number | undefined;
  readonly ipClass: string;
  readonly normalizedIp: string | null;
}

export interface ValidationFailure {
  readonly ok: false;
  readonly code: UrlGuardErrorCode;
  readonly detail: string;
  readonly input?: string;
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

export interface HopResult {
  readonly url: string;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly addresses: readonly string[];
  readonly pinnedIp: string | null;
  readonly crossOrigin: boolean;
}

export interface ChainResult {
  readonly ok: boolean;
  readonly hops: readonly HopResult[];
  readonly finalUrl?: string;
  readonly code?: UrlGuardErrorCode;
  readonly detail?: string;
  readonly hop?: number;
  readonly input?: string;
}

export interface SafeFetchOptions extends ValidateOptions {
  readonly fetch?: typeof globalThis.fetch;
}

export interface ScanFinding extends ValidationResult {
  readonly path: string;
  readonly value: string;
}

export interface ScanResult {
  readonly ok: boolean;
  readonly findings: readonly ScanFinding[];
  readonly rejected: number;
  readonly scanned: number;
  readonly truncated: boolean;
}

export interface ScanOptions extends ValidateOptions {
  readonly maxDepth?: number;
  readonly maxNodes?: number;
  readonly options?: ValidateOptions;
}

export interface Guard {
  validate(input: string): ValidationResult;
  assert(input: string): ValidationSuccess;
  isPublicHostname(hostname: string): boolean;
  readonly options: Readonly<ValidateOptions>;
}

export interface IpParseResult6 {
  readonly [index: number]: number;
  readonly length: 8;
}

export declare function validateUrl(input: unknown, options?: ValidateOptions): ValidationResult;
export declare function assertSafeUrl(input: unknown, options?: ValidateOptions): ValidationSuccess;
export declare function validateRedirectChain(
  urls: string | Iterable<string>,
  options?: ValidateOptions
): Promise<ChainResult>;
export declare function createGuard(options?: ValidateOptions): Guard;
export declare function createSafeFetch(
  options?: SafeFetchOptions
): (input: string | { url: string }, init?: RequestInit) => Promise<Response>;
export declare function scanToolArguments(value: unknown, options?: ScanOptions): ScanResult;
export declare function isPublicHostname(hostname: string, options?: ValidateOptions): boolean;

export declare function parseIpv4(host: string): string | null;
export declare function parseIpv6(host: string): number[] | null;
export declare function normalizeIp(host: string): string | null;
export declare function classifyIp(host: string): string;
export declare function mappedIpv4(groups: readonly number[] | null): string | null;
export declare function sixToFourIpv4(groups: readonly number[] | null): string | null;
export declare function nat64Ipv4(groups: readonly number[] | null): string | null;
export declare function isNat64LocalUse(groups: readonly number[] | null): boolean;
export declare function ipv4CompatibleIpv4(groups: readonly number[] | null): string | null;
export declare function siitIpv4(groups: readonly number[] | null): string | null;
export declare function isTeredo(groups: readonly number[] | null): boolean;
export declare function teredoClientIpv4(groups: readonly number[] | null): string | null;
export declare function formatIpv6(groups: readonly number[] | null): string | null;
export declare function ipv4ToUint32(ip: string): number | null;

export type ParsedCidr =
  | { readonly family: 4; readonly value: number; readonly bits: number }
  | { readonly family: 6; readonly groups: readonly number[]; readonly bits: number };

export declare function parseCidr(cidr: string): ParsedCidr | null;
export declare function cidrContains(cidr: string, address: string): boolean;

export interface ResolveSuccess {
  readonly ok: true;
  readonly addresses: readonly string[];
  readonly skipped?: boolean;
  readonly pinnedIp?: string;
}

export interface ResolveFailure {
  readonly ok: false;
  readonly code: UrlGuardErrorCode;
  readonly detail: string;
  readonly input?: string;
}

export type ResolveResult = ResolveSuccess | ResolveFailure;

export declare function resolveSafe(
  hostname: string,
  options?: ValidateOptions,
  baseOptions?: ValidateOptions
): Promise<ResolveResult>;

export declare const DEFAULT_OPTIONS: Readonly<{
  readonly allowedSchemes: readonly ['https:'];
  readonly allowUserinfo: false;
  readonly allowedPorts: 'default-only';
  readonly idna: 'ascii-only';
  readonly maxInputLength: 8192;
  readonly checkRebinding: false;
  readonly rebindDelayMs: 50;
  readonly maxRedirects: 5;
}>;

export declare const VERSION: string;
