import {
  AuthorityMappingResult,
  AuthorityMappingRule,
  RuleEvaluation,
  RuleType,
} from './permission.models';
import { KeyMaterial, SignatureResult } from './signature.models';

export type HttpStatusInput = '401' | '403' | 'unknown';
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export const HTTP_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

export type SignatureMode = 'skip' | 'use-verifier' | 'verify-now';

export interface TroubleshooterInput {
  token: string;
  httpStatus: HttpStatusInput;
  method: HttpMethod;
  endpoint: string;
  expectedIssuer: string;
  expectedAudience: string;
  requiredRoles: string;
  requiredScopes: string;
  requiredAuthorities: string;
  ruleType: RuleType;
  /** Optional Spring Security expression that overrides the rule built from the fields. */
  customExpression: string;
  clockSkewSeconds: number;
  springMode: boolean;
  mappingRules: AuthorityMappingRule[];
  signatureMode: SignatureMode;
}

export type StepStatus = 'passed' | 'failed' | 'warning' | 'not-verified' | 'not-applicable';

export const STEP_STATUS_LABEL: Record<StepStatus, string> = {
  passed: 'Passed',
  failed: 'Failed',
  warning: 'Warning',
  'not-verified': 'Not Verified',
  'not-applicable': 'Not Applicable',
};

export type StepId =
  | 'structure'
  | 'decoding'
  | 'signature'
  | 'temporal'
  | 'issuer'
  | 'audience'
  | 'claims'
  | 'mapping'
  | 'permission'
  | 'final';

export interface StepDatum {
  label: string;
  value: string;
}

export interface DiagnosticStep {
  id: StepId;
  index: number;
  title: string;
  status: StepStatus;
  summary: string;
  analyzed: string;
  data: StepDatum[];
  evidence: string[];
  impact: string | null;
  explanation: string;
  recommendations: string[];
}

/**
 * confirmed — proven by local data (e.g. exp in the past, missing authority under the configured rule).
 * likely    — strongly suggested by local data but depends on server configuration.
 * possible  — hypothesis that cannot be checked without access to the server.
 */
export type CauseConfidence = 'confirmed' | 'likely' | 'possible';
export type CauseCategory = 'authentication' | 'authorization' | 'configuration';

export interface DiagnosisCause {
  id: string;
  title: string;
  category: CauseCategory;
  confidence: CauseConfidence;
  stepId: StepId;
  reason: string;
  evidence: string[];
  recommendation: string;
}

export type LocalOutcome =
  | 'authentication-failure'
  | 'authorization-failure'
  | 'no-issue-detected'
  | 'insufficient-information';

export interface DiagnosisHeadline {
  title: string;
  tone: 'danger' | 'warning' | 'success' | 'neutral';
  description: string;
  simulatedDecision:
    'Access Denied — Simulated' | 'Access Granted — Simulated' | 'Rejected — Simulated' | null;
}

export interface DiagnosisCounts {
  passed: number;
  failed: number;
  warning: number;
  notVerified: number;
  notApplicable: number;
}

export interface DiagnosisResult {
  analyzedAt: number;
  httpStatus: HttpStatusInput;
  method: HttpMethod;
  endpoint: string;
  steps: DiagnosticStep[];
  counts: DiagnosisCounts;
  causes: DiagnosisCause[];
  hypotheses: DiagnosisCause[];
  mostLikely: DiagnosisCause | null;
  outcome: LocalOutcome;
  headline: DiagnosisHeadline;
  statusNote: string | null;
  recommendations: string[];
  mapping: AuthorityMappingResult | null;
  evaluation: RuleEvaluation | null;
  signature: SignatureResult | null;
  suggestedMapping: AuthorityMappingRule[] | null;
}

export interface TroubleshooterPreset {
  input: Partial<TroubleshooterInput>;
  autoRun: boolean;
  /** Key used for "verify-now" mode (demo or freshly generated test keys). */
  verificationKey?: KeyMaterial;
  label?: string;
}
