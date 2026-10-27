export type PermissionKind = 'role' | 'scope' | 'authority';

export interface PermissionSource {
  path: string;
  kind: PermissionKind;
}

export interface PermissionClaimMatch {
  path: string;
  kind: PermissionKind;
  values: string[];
}

export interface ExtractedPermissions {
  roles: string[];
  scopes: string[];
  authorities: string[];
  matches: PermissionClaimMatch[];
}

/**
 * Mirrors Spring Security's JwtGrantedAuthoritiesConverter configuration.
 * `claim` accepts alternatives separated by "|" (first present wins, like the
 * default "scope|scp" lookup) and dot paths for nested claims.
 */
export interface AuthorityMappingRule {
  claim: string;
  prefix: string;
  delimiter: string;
}

export interface AuthorityMappingTrace {
  rule: AuthorityMappingRule;
  claimUsed: string | null;
  rawValues: string[];
  mapped: string[];
  note: string;
}

export interface AuthorityMappingResult {
  authorities: string[];
  traces: AuthorityMappingTrace[];
}

export type RuleType =
  | 'hasRole'
  | 'hasAnyRole'
  | 'hasAuthority'
  | 'hasAnyAuthority'
  | 'hasAllAuthorities'
  | 'customAnd'
  | 'customOr';

export const RULE_TYPE_OPTIONS: { value: RuleType; label: string; hint: string }[] = [
  { value: 'hasRole', label: 'hasRole', hint: 'Requires the role (ROLE_ prefix added by Spring)' },
  { value: 'hasAnyRole', label: 'hasAnyRole', hint: 'Requires at least one of the roles' },
  { value: 'hasAuthority', label: 'hasAuthority', hint: 'Requires the exact authority string' },
  { value: 'hasAnyAuthority', label: 'hasAnyAuthority', hint: 'Requires at least one authority' },
  {
    value: 'hasAllAuthorities',
    label: 'hasAllAuthorities',
    hint: 'Requires every listed authority',
  },
  {
    value: 'customAnd',
    label: 'Custom AND',
    hint: 'All roles, scopes and authorities are required',
  },
  { value: 'customOr', label: 'Custom OR', hint: 'Any role, scope or authority grants access' },
];

export type MatchMode = 'spring' | 'lenient';

export type ExpressionNode =
  | { type: 'call'; fn: string; args: string[] }
  | { type: 'and' | 'or'; left: ExpressionNode; right: ExpressionNode }
  | { type: 'not'; expr: ExpressionNode };

export interface ExpressionCheck {
  expression: string;
  fn: string;
  required: string[];
  matched: string[];
  missing: string[];
  result: boolean;
  /** Token authorities that differ from a missing requirement only by prefix or case. */
  nearMatches: NearMatch[];
}

export interface NearMatch {
  required: string;
  found: string;
  reason: 'role-prefix' | 'scope-prefix' | 'case' | 'other-prefix';
}

export interface RuleEvaluation {
  expression: string;
  parsed: boolean;
  parseError?: string;
  granted: boolean;
  checks: ExpressionCheck[];
  warnings: string[];
}

export interface RequirementInput {
  ruleType: RuleType;
  roles: string[];
  scopes: string[];
  authorities: string[];
}
