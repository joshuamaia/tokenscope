import { Injectable, inject } from '@angular/core';
import { DecodedJwt } from '../models/jwt.models';
import {
  SEVERITY_ORDER,
  SEVERITY_PENALTY,
  SecurityFinding,
  SecurityPolicy,
  SecurityReport,
  SecurityRuleDoc,
  Severity,
} from '../models/security.models';
import { formatDuration, toIso } from '../utils/time-format';
import { ClockService } from './clock.service';
import { isNumericDate } from './jwt-claims.service';
import { ALGORITHMS } from './jwt-signature.service';

export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
  maxLifetimeMinutes: 60,
  requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
  allowedAlgorithms: [
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512',
    'ES256',
    'ES384',
    'ES512',
    'EdDSA',
    'HS256',
    'HS384',
    'HS512',
  ],
  clockSkewSeconds: 60,
};

/** Every rule evaluated by the analyzer (documented in the README). */
export const SECURITY_RULES: SecurityRuleDoc[] = [
  { id: 'TS-01', title: 'Algorithm "none"', severity: 'critical' },
  { id: 'TS-02', title: 'Missing expiration (exp)', severity: 'high' },
  { id: 'TS-03', title: 'Token expired', severity: 'medium' },
  { id: 'TS-04', title: 'Token not yet valid', severity: 'low' },
  { id: 'TS-05', title: 'Excessive token lifetime', severity: 'medium' },
  { id: 'TS-06', title: 'iat later than exp', severity: 'high' },
  { id: 'TS-07', title: 'nbf later than exp', severity: 'high' },
  { id: 'TS-08', title: 'iat in the future', severity: 'medium' },
  { id: 'TS-09', title: 'Missing issuer (iss)', severity: 'medium' },
  { id: 'TS-10', title: 'Missing audience (aud)', severity: 'medium' },
  { id: 'TS-11', title: 'Missing subject (sub)', severity: 'low' },
  { id: 'TS-12', title: 'Invalid temporal claims', severity: 'high' },
  { id: 'TS-13', title: 'Unsupported or unknown algorithm', severity: 'high' },
  { id: 'TS-14', title: 'Unrecognized critical header parameters', severity: 'high' },
  { id: 'TS-15', title: 'Policy violation', severity: 'medium' },
  { id: 'TS-16', title: 'Key referenced by the token header', severity: 'medium' },
  { id: 'TS-17', title: 'Sensitive data in payload', severity: 'high' },
  { id: 'TS-18', title: 'Symmetric algorithm (shared secret)', severity: 'info' },
];

const SENSITIVE_CLAIM =
  /^(password|passwd|pwd|secret|client_secret|api[_-]?key|private[_-]?key|credit[_-]?card|card[_-]?number|cvv|ssn|cpf)$/i;

/**
 * Static analysis of a decoded JWT against a configurable policy. The score
 * expresses policy conformance only — never a security guarantee.
 */
@Injectable({ providedIn: 'root' })
export class JwtSecurityAnalyzerService {
  private readonly clock = inject(ClockService);

  analyze(decoded: DecodedJwt, policy: SecurityPolicy = DEFAULT_SECURITY_POLICY): SecurityReport {
    const now = this.clock.now() / 1000;
    const findings: SecurityFinding[] = [];
    const header = decoded.header ?? {};
    const payload = decoded.payload ?? {};
    const add = (
      ruleId: string,
      f: Omit<SecurityFinding, 'ruleId' | 'title' | 'severity'> & {
        severity?: Severity;
        title?: string;
      },
    ) => {
      const rule = SECURITY_RULES.find((r) => r.id === ruleId)!;
      findings.push({
        ruleId,
        title: f.title ?? rule.title,
        severity: f.severity ?? rule.severity,
        description: f.description,
        evidence: f.evidence,
        impact: f.impact,
        recommendation: f.recommendation,
      });
    };

    const alg = decoded.alg ?? '';
    if (alg.toLowerCase() === 'none') {
      add('TS-01', {
        description: 'The token is unsigned: anyone can create or modify it.',
        evidence: `header.alg = "${alg}"`,
        impact:
          'If a server accepts it, an attacker can impersonate any user or escalate privileges.',
        recommendation: 'Reject unsigned tokens and pin the accepted algorithms on the server.',
      });
    } else if (alg && !ALGORITHMS[alg]) {
      add('TS-13', {
        description: `"${alg}" is not a registered JWS signing algorithm supported by common libraries.`,
        evidence: `header.alg = "${alg}"`,
        impact: 'The token will be rejected or verified by a non-standard implementation.',
        recommendation: 'Use a standard algorithm such as RS256, PS256, ES256 or EdDSA.',
      });
    } else if (alg && !policy.allowedAlgorithms.includes(alg)) {
      add('TS-15', {
        title: 'Algorithm not allowed by policy',
        description: `${alg} is not in the allowed algorithm list of the policy.`,
        evidence: `Allowed: ${policy.allowedAlgorithms.join(', ')}`,
        impact: 'Servers configured with this policy would reject the token.',
        recommendation: 'Align the issuer signing algorithm with the policy.',
      });
    }
    if (alg.startsWith('HS')) {
      add('TS-18', {
        description: 'HMAC uses one shared secret for signing and verification.',
        evidence: `header.alg = "${alg}"`,
        impact:
          'Every service able to verify the token can also mint valid tokens. Secret leaks compromise all of them.',
        recommendation:
          'Prefer asymmetric algorithms (RS256/ES256/EdDSA) when tokens are verified by multiple services.',
      });
    }

    const crit = header['crit'];
    if (Array.isArray(crit) && crit.length) {
      add('TS-14', {
        description:
          'The header lists critical extensions that TokenScope (and most libraries) do not understand.',
        evidence: `crit = ${JSON.stringify(crit)}`,
        impact: 'RFC 7515 requires rejecting tokens with unrecognized critical parameters.',
        recommendation:
          'Remove unsupported "crit" entries or make sure every verifier implements them.',
      });
    }
    const keyRefs = ['jku', 'x5u', 'jwk'].filter((p) => p in header);
    if (keyRefs.length) {
      add('TS-16', {
        description: 'The header tells the verifier where to find the key.',
        evidence: keyRefs.map((p) => `${p} = ${JSON.stringify(header[p])}`).join('; '),
        impact:
          'Verifiers that trust these parameters can be tricked into using an attacker-controlled key.',
        recommendation:
          'Verify tokens only with keys from a trusted, pre-configured JWKS URI. Ignore jku/x5u/jwk unless allow-listed.',
      });
    }

    // Temporal rules
    const temporal = ['exp', 'nbf', 'iat'] as const;
    const invalid = temporal.filter((c) => c in payload && !isNumericDate(payload[c]));
    const millis = temporal.filter(
      (c) => isNumericDate(payload[c]) && (payload[c] as number) > 1e11,
    );
    if (invalid.length || millis.length) {
      add('TS-12', {
        description: invalid.length
          ? 'Temporal claims must be NumericDate values (seconds since epoch).'
          : 'Temporal claims look like milliseconds instead of seconds.',
        evidence: [...invalid, ...millis]
          .map((c) => `${c} = ${JSON.stringify(payload[c])}`)
          .join('; '),
        impact: 'Validators may reject the token or treat it as valid for thousands of years.',
        recommendation: 'Emit exp, nbf and iat as integers in seconds.',
      });
    }
    const exp =
      isNumericDate(payload['exp']) && !millis.includes('exp') ? (payload['exp'] as number) : null;
    const nbf =
      isNumericDate(payload['nbf']) && !millis.includes('nbf') ? (payload['nbf'] as number) : null;
    const iat =
      isNumericDate(payload['iat']) && !millis.includes('iat') ? (payload['iat'] as number) : null;

    if (!('exp' in payload)) {
      add('TS-02', {
        description: 'The token never expires by itself.',
        evidence: '"exp" claim is absent',
        impact: 'A leaked token can be replayed indefinitely.',
        recommendation: 'Always issue access tokens with a short "exp".',
      });
    }
    if (exp !== null && now - policy.clockSkewSeconds >= exp) {
      add('TS-03', {
        description: 'The token is past its expiration time.',
        evidence: `exp = ${toIso(exp * 1000)} (${formatDuration(now - exp)} ago)`,
        impact: 'Resource servers will reject it with HTTP 401.',
        recommendation: 'Obtain a fresh token; ensure clients refresh tokens before expiry.',
      });
    }
    if (nbf !== null && now + policy.clockSkewSeconds < nbf) {
      add('TS-04', {
        description: 'The token cannot be used yet.',
        evidence: `nbf = ${toIso(nbf * 1000)} (in ${formatDuration(nbf - now)})`,
        impact: 'Requests fail with HTTP 401 until nbf is reached — often caused by clock drift.',
        recommendation: 'Synchronize clocks (NTP) or verify the issuer configuration.',
      });
    }
    const start = nbf ?? iat;
    if (exp !== null && start !== null && exp > start) {
      const lifetimeMin = (exp - start) / 60;
      if (lifetimeMin > policy.maxLifetimeMinutes) {
        add('TS-05', {
          severity: lifetimeMin > 24 * 60 ? 'high' : 'medium',
          description: `The validity window exceeds the policy maximum of ${policy.maxLifetimeMinutes} minutes.`,
          evidence: `Lifetime: ${formatDuration(exp - start)}`,
          impact: 'Longer lifetimes widen the window for replay of a stolen token.',
          recommendation: `Reduce the access token lifetime to ${policy.maxLifetimeMinutes} minutes or less and use refresh tokens.`,
        });
      }
    }
    if (iat !== null && exp !== null && iat > exp) {
      add('TS-06', {
        description: 'The token was issued after its own expiration.',
        evidence: `iat = ${toIso(iat * 1000)}, exp = ${toIso(exp * 1000)}`,
        impact: 'Inconsistent tokens indicate an issuer bug or manual crafting.',
        recommendation: 'Fix the issuer clock or token generation logic.',
      });
    }
    if (nbf !== null && exp !== null && nbf > exp) {
      add('TS-07', {
        description: 'The validity window is empty: nbf is after exp.',
        evidence: `nbf = ${toIso(nbf * 1000)}, exp = ${toIso(exp * 1000)}`,
        impact: 'The token can never be valid.',
        recommendation: 'Fix the issuer token generation logic.',
      });
    }
    if (iat !== null && iat - policy.clockSkewSeconds > now) {
      add('TS-08', {
        description: 'The issue time is in the future.',
        evidence: `iat = ${toIso(iat * 1000)} (in ${formatDuration(iat - now)})`,
        impact: 'Indicates clock drift on the issuer or a crafted token.',
        recommendation: 'Synchronize the issuer clock (NTP).',
      });
    }

    // Identity claims
    if (!('iss' in payload)) {
      add('TS-09', {
        description: 'The token does not state who issued it.',
        evidence: '"iss" claim is absent',
        impact:
          'Servers cannot bind the token to a trusted issuer; tokens from other issuers may be accepted.',
        recommendation: 'Include "iss" and validate it on the resource server (issuer-uri).',
      });
    }
    if (!('aud' in payload)) {
      add('TS-10', {
        description: 'The token is not bound to a specific API.',
        evidence: '"aud" claim is absent',
        impact: 'A token issued for one service can be replayed against another (confused deputy).',
        recommendation: 'Include "aud" and validate it on every resource server.',
      });
    }
    if (!('sub' in payload)) {
      add('TS-11', {
        description: 'The token does not identify its principal.',
        evidence: '"sub" claim is absent',
        impact: 'Auditing and per-user authorization become unreliable.',
        recommendation: 'Include a stable, non-personal subject identifier.',
      });
    }
    const covered = ['exp', 'iss', 'aud', 'sub'];
    const missingPolicy = policy.requiredClaims.filter(
      (c) => !covered.includes(c) && !(c in payload),
    );
    if (missingPolicy.length) {
      add('TS-15', {
        title: 'Required claims missing (policy)',
        description: 'The token lacks claims required by the configured policy.',
        evidence: `Missing: ${missingPolicy.join(', ')}`,
        impact: 'Servers enforcing this policy would reject the token.',
        recommendation: 'Configure the issuer to include every required claim.',
      });
    }
    const sensitive = Object.keys(payload).filter((k) => SENSITIVE_CLAIM.test(k));
    if (sensitive.length) {
      add('TS-17', {
        description:
          'JWT payloads are only Base64URL-encoded, not encrypted — anyone holding the token can read them.',
        evidence: `Claims: ${sensitive.join(', ')}`,
        impact: 'Secrets or personal data are exposed in logs, browsers and proxies.',
        recommendation: 'Remove sensitive values from the token; keep them server-side or use JWE.',
      });
    }

    findings.sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );
    const counts = Object.fromEntries(
      SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]),
    ) as Record<Severity, number>;
    const penalty = findings.reduce((sum, f) => sum + SEVERITY_PENALTY[f.severity], 0);
    const score = Math.max(0, 100 - penalty);
    const failedIds = new Set(findings.map((f) => f.ruleId));
    return {
      score,
      grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
      findings,
      counts,
      passedRules: SECURITY_RULES.filter((r) => !failedIds.has(r.id)).map(
        (r) => `${r.id} ${r.title}`,
      ),
      analyzedAt: this.clock.now(),
    };
  }
}
