export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Points deducted from the score per finding. Documented in the README. */
export const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

export interface SecurityFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string;
  impact: string;
  recommendation: string;
}

export interface SecurityPolicy {
  maxLifetimeMinutes: number;
  requiredClaims: string[];
  allowedAlgorithms: string[];
  clockSkewSeconds: number;
}

export interface SecurityReport {
  score: number;
  grade: string;
  findings: SecurityFinding[];
  counts: Record<Severity, number>;
  passedRules: string[];
  analyzedAt: number;
}

export interface SecurityRuleDoc {
  id: string;
  title: string;
  severity: Severity;
}
