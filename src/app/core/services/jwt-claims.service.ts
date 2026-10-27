import { Injectable } from '@angular/core';
import { ClaimDoc, ClaimView, JwtIssue, JwtPayload } from '../models/jwt.models';
import { isPlainObject, safeStringify } from '../utils/json-path';

export const CLAIM_DOCS: Record<string, ClaimDoc> = {
  iss: {
    name: 'iss',
    label: 'Issuer',
    category: 'registered',
    spec: 'RFC 7519 §4.1.1',
    description:
      'Identifies the principal that issued the JWT (usually the authorization server URL). Resource servers typically validate it against a configured issuer.',
  },
  sub: {
    name: 'sub',
    label: 'Subject',
    category: 'registered',
    spec: 'RFC 7519 §4.1.2',
    description:
      'Identifies the principal that is the subject of the JWT — usually the user or client ID.',
  },
  aud: {
    name: 'aud',
    label: 'Audience',
    category: 'registered',
    spec: 'RFC 7519 §4.1.3',
    description:
      'Recipients the JWT is intended for. A resource server should reject tokens whose audience does not include it.',
  },
  exp: {
    name: 'exp',
    label: 'Expiration Time',
    category: 'registered',
    spec: 'RFC 7519 §4.1.4',
    description:
      'NumericDate (seconds since epoch) on or after which the JWT must not be accepted.',
  },
  nbf: {
    name: 'nbf',
    label: 'Not Before',
    category: 'registered',
    spec: 'RFC 7519 §4.1.5',
    description: 'NumericDate before which the JWT must not be accepted.',
  },
  iat: {
    name: 'iat',
    label: 'Issued At',
    category: 'registered',
    spec: 'RFC 7519 §4.1.6',
    description: 'NumericDate at which the JWT was issued. Useful to determine the token age.',
  },
  jti: {
    name: 'jti',
    label: 'JWT ID',
    category: 'registered',
    spec: 'RFC 7519 §4.1.7',
    description:
      'Unique identifier of the token. Can be used to prevent replay or to revoke tokens.',
  },
  roles: {
    name: 'roles',
    label: 'Roles',
    category: 'permission',
    description:
      'Custom claim commonly used to carry user roles. Spring Security does not map it by default — a JwtGrantedAuthoritiesConverter must be configured.',
  },
  authorities: {
    name: 'authorities',
    label: 'Authorities',
    category: 'permission',
    description:
      'Custom claim with granted authorities (e.g. ROLE_ADMIN, READ). Must be explicitly mapped in Spring Security.',
  },
  scope: {
    name: 'scope',
    label: 'Scope',
    category: 'permission',
    spec: 'RFC 8693 §4.2',
    description:
      'Space-delimited OAuth 2.0 scopes. Spring Security maps each value to SCOPE_<value> by default.',
  },
  scp: {
    name: 'scp',
    label: 'Scopes (scp)',
    category: 'permission',
    description:
      'Alternative scope claim (Azure AD / Okta). Spring Security reads it when "scope" is absent and prefixes values with SCOPE_.',
  },
  azp: {
    name: 'azp',
    label: 'Authorized Party',
    category: 'identity',
    spec: 'OpenID Connect Core §2',
    description: 'The client to which the token was issued.',
  },
  client_id: {
    name: 'client_id',
    label: 'Client ID',
    category: 'identity',
    spec: 'RFC 9068 §2.2',
    description: 'OAuth 2.0 client identifier that requested the token.',
  },
  realm_access: {
    name: 'realm_access',
    label: 'Realm Access',
    category: 'permission',
    description: 'Keycloak realm-level roles (realm_access.roles).',
  },
  resource_access: {
    name: 'resource_access',
    label: 'Resource Access',
    category: 'permission',
    description: 'Keycloak client-level roles (resource_access.<client>.roles).',
  },
  groups: {
    name: 'groups',
    label: 'Groups',
    category: 'permission',
    description: 'Group memberships issued by the identity provider.',
  },
  permissions: {
    name: 'permissions',
    label: 'Permissions',
    category: 'permission',
    description: 'Fine-grained permissions (e.g. Auth0 RBAC).',
  },
  email: {
    name: 'email',
    label: 'Email',
    category: 'identity',
    description: 'End-user e-mail address (OpenID Connect).',
  },
  name: {
    name: 'name',
    label: 'Name',
    category: 'identity',
    description: 'End-user full name (OpenID Connect).',
  },
  preferred_username: {
    name: 'preferred_username',
    label: 'Preferred Username',
    category: 'identity',
    description: 'Shorthand name of the end user (OpenID Connect).',
  },
  sid: {
    name: 'sid',
    label: 'Session ID',
    category: 'identity',
    description: 'Identifier of the authentication session.',
  },
  auth_time: {
    name: 'auth_time',
    label: 'Authentication Time',
    category: 'identity',
    description: 'NumericDate when the end-user authentication occurred.',
  },
  nonce: {
    name: 'nonce',
    label: 'Nonce',
    category: 'identity',
    description:
      'Value used to associate a client session with an ID Token and mitigate replay attacks.',
  },
  typ: {
    name: 'typ',
    label: 'Type',
    category: 'custom',
    description: 'Token type as set by the issuer (e.g. Bearer).',
  },
};

export const HEADER_DOCS: Record<string, string> = {
  alg: 'Algorithm used to sign the token (e.g. HS256, RS256). "none" means the token is unsigned.',
  typ: 'Media type of the token — usually "JWT" or "at+jwt" for OAuth 2.0 access tokens (RFC 9068).',
  kid: 'Key ID — hint that tells the verifier which key from a JWKS signed the token.',
  cty: 'Content type — used for nested JWTs.',
  jku: 'JWK Set URL. Never trust it blindly: an attacker can point it to their own keys.',
  jwk: 'Embedded public key. Never trust it blindly: anyone can embed their own key.',
  x5u: 'URL of an X.509 certificate chain. Must not be trusted without validation.',
  x5c: 'Embedded X.509 certificate chain.',
  x5t: 'SHA-1 thumbprint of the X.509 certificate.',
  'x5t#S256': 'SHA-256 thumbprint of the X.509 certificate.',
  crit: 'Extensions that the verifier MUST understand; otherwise the token must be rejected.',
  enc: 'Content encryption algorithm (JWE only).',
  zip: 'Compression algorithm (JWE only).',
};

const NUMERIC_DATE_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time'];
const STRING_CLAIMS = ['iss', 'sub', 'jti', 'azp', 'client_id'];

@Injectable({ providedIn: 'root' })
export class JwtClaimsService {
  /** Validates the JSON types of registered and well-known claims. */
  validateTypes(payload: JwtPayload): JwtIssue[] {
    const issues: JwtIssue[] = [];
    const add = (code: string, message: string) =>
      issues.push({ code, severity: 'error', segment: 'payload', message });

    for (const claim of NUMERIC_DATE_CLAIMS) {
      if (claim in payload && !isNumericDate(payload[claim])) {
        add(
          `claim-type-${claim}`,
          `Claim "${claim}" must be a NumericDate (seconds since epoch), got ${describeType(payload[claim])}.`,
        );
      }
    }
    for (const claim of STRING_CLAIMS) {
      if (claim in payload && typeof payload[claim] !== 'string') {
        add(
          `claim-type-${claim}`,
          `Claim "${claim}" must be a string, got ${describeType(payload[claim])}.`,
        );
      }
    }
    if ('aud' in payload) {
      const aud = payload['aud'];
      const ok =
        typeof aud === 'string' || (Array.isArray(aud) && aud.every((a) => typeof a === 'string'));
      if (!ok)
        add(
          'claim-type-aud',
          `Claim "aud" must be a string or an array of strings, got ${describeType(aud)}.`,
        );
    }
    if (
      'scope' in payload &&
      typeof payload['scope'] !== 'string' &&
      !isStringArray(payload['scope'])
    ) {
      add(
        'claim-type-scope',
        `Claim "scope" should be a space-delimited string, got ${describeType(payload['scope'])}.`,
      );
    }
    for (const claim of ['roles', 'authorities', 'scp', 'groups', 'permissions']) {
      if (
        claim in payload &&
        typeof payload[claim] !== 'string' &&
        !isStringArray(payload[claim])
      ) {
        add(
          `claim-type-${claim}`,
          `Claim "${claim}" should be a string or an array of strings, got ${describeType(payload[claim])}.`,
        );
      }
    }
    for (const claim of NUMERIC_DATE_CLAIMS) {
      const value = payload[claim];
      if (typeof value === 'number' && value > 1e11) {
        issues.push({
          code: `claim-ms-${claim}`,
          severity: 'warning',
          segment: 'payload',
          message: `Claim "${claim}" looks like milliseconds (${value}). NumericDate must be expressed in seconds.`,
        });
      }
    }
    return issues;
  }

  describe(payload: JwtPayload): ClaimView[] {
    const typeIssues = this.validateTypes(payload);
    return Object.entries(payload).map(([key, value]) => {
      const doc = CLAIM_DOCS[key] ?? null;
      const view: ClaimView = {
        key,
        value,
        display: displayValue(value),
        type: describeType(value),
        doc,
        issue: typeIssues.find(
          (i) => i.code === `claim-type-${key}` || i.code === `claim-ms-${key}`,
        )?.message,
      };
      if (NUMERIC_DATE_CLAIMS.includes(key) && isNumericDate(value)) {
        view.timestamp = value * 1000;
      }
      return view;
    });
  }

  audiences(payload: JwtPayload | null): string[] {
    const aud = payload?.['aud'];
    if (typeof aud === 'string') return [aud];
    if (Array.isArray(aud)) return aud.filter((a): a is string => typeof a === 'string');
    return [];
  }

  numericDate(payload: JwtPayload | null, claim: 'exp' | 'nbf' | 'iat'): number | null {
    const value = payload?.[claim];
    return isNumericDate(value) ? value : null;
  }
}

export function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

export function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

export function describeType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function displayValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.every((v) => typeof v !== 'object')) return value.join(', ');
  if (isPlainObject(value) || Array.isArray(value)) return safeStringify(value, 0);
  return String(value);
}
