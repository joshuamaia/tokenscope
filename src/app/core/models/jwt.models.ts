import { JsonObject } from '../utils/json-path';

export const MAX_TOKEN_LENGTH = 64 * 1024;

export type JwtHeader = JsonObject;
export type JwtPayload = JsonObject;

export type TokenKind = 'empty' | 'jws' | 'jwe' | 'unknown';
export type JwtSegment = 'header' | 'payload' | 'signature' | 'token';

export type IssueSeverity = 'error' | 'warning' | 'info';

export interface JwtIssue {
  code: string;
  severity: IssueSeverity;
  segment: JwtSegment;
  message: string;
}

export interface JwtSegments {
  header: string;
  payload: string;
  signature: string;
}

export interface DecodedJwt {
  /** Normalized compact token (whitespace and "Bearer " prefix removed). */
  token: string;
  kind: TokenKind;
  /** True when header and payload were decoded into JSON objects. */
  decoded: boolean;
  /** True when no structural errors were found. */
  valid: boolean;
  segments: JwtSegments | null;
  segmentCount: number;
  header: JwtHeader | null;
  payload: JwtPayload | null;
  signatureLength: number;
  alg: string | null;
  issues: JwtIssue[];
}

export type ClaimCategory = 'registered' | 'permission' | 'identity' | 'custom';

export interface ClaimDoc {
  name: string;
  label: string;
  description: string;
  category: ClaimCategory;
  spec?: string;
}

export interface ClaimView {
  key: string;
  value: unknown;
  display: string;
  type: string;
  doc: ClaimDoc | null;
  timestamp?: number;
  issue?: string;
}
