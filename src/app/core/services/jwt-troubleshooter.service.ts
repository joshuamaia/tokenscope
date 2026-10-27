import { Injectable, inject } from '@angular/core';
import {
  CauseConfidence,
  DiagnosisCause,
  DiagnosisCounts,
  DiagnosisHeadline,
  DiagnosisResult,
  DiagnosticStep,
  LocalOutcome,
  STEP_STATUS_LABEL,
  StepDatum,
  StepId,
  StepStatus,
  TroubleshooterInput,
} from '../models/diagnosis.models';
import { DecodedJwt } from '../models/jwt.models';
import {
  AuthorityMappingResult,
  AuthorityMappingRule,
  ExtractedPermissions,
  RuleEvaluation,
} from '../models/permission.models';
import { SignatureResult } from '../models/signature.models';
import { splitList } from '../utils/json-path';
import { formatDateTime, formatDuration, toIso } from '../utils/time-format';
import { ClockService } from './clock.service';
import { JwtClaimsService } from './jwt-claims.service';
import { JwtDecoderService } from './jwt-decoder.service';
import { JwtPermissionService, stripPrefix } from './jwt-permission.service';
import { ALGORITHMS } from './jwt-signature.service';
import { JwtTimelineService } from './jwt-timeline.service';

const STEP_TITLES: Record<StepId, string> = {
  structure: 'Token Structure',
  decoding: 'Token Decoding',
  signature: 'Signature Verification',
  temporal: 'Temporal Validation',
  issuer: 'Issuer Validation',
  audience: 'Audience Validation',
  claims: 'Claims Extraction',
  mapping: 'Authority Mapping',
  permission: 'Permission Evaluation',
  final: 'Final Diagnosis',
};

const STEP_ORDER: StepId[] = [
  'structure',
  'decoding',
  'signature',
  'temporal',
  'issuer',
  'audience',
  'claims',
  'mapping',
  'permission',
  'final',
];

const CONFIDENCE_RANK: Record<CauseConfidence, number> = { confirmed: 0, likely: 1, possible: 2 };

export const DEFAULT_TROUBLESHOOTER_INPUT: TroubleshooterInput = {
  token: '',
  httpStatus: '403',
  method: 'GET',
  endpoint: '/api/admin/users',
  expectedIssuer: '',
  expectedAudience: '',
  requiredRoles: '',
  requiredScopes: '',
  requiredAuthorities: '',
  ruleType: 'hasRole',
  customExpression: '',
  clockSkewSeconds: 60,
  springMode: true,
  mappingRules: [{ claim: 'scope|scp', prefix: 'SCOPE_', delimiter: ' ' }],
  signatureMode: 'skip',
};

type StepDraft = Omit<DiagnosticStep, 'id' | 'index' | 'title'>;

interface Context {
  input: TroubleshooterInput;
  now: number;
  causes: DiagnosisCause[];
  hypotheses: DiagnosisCause[];
}

/**
 * Builds an evidence-based diagnosis for HTTP 401/403 failures. Every cause is
 * tagged with a confidence: "confirmed" only when the local data proves it.
 * The service never claims what the real server will decide.
 */
@Injectable({ providedIn: 'root' })
export class JwtTroubleshooterService {
  private readonly decoder = inject(JwtDecoderService);
  private readonly claims = inject(JwtClaimsService);
  private readonly timeline = inject(JwtTimelineService);
  private readonly permissions = inject(JwtPermissionService);
  private readonly clock = inject(ClockService);

  /** The expression actually evaluated for the given input. */
  requirementExpression(input: TroubleshooterInput): string {
    if (input.customExpression.trim()) return input.customExpression.trim();
    return this.permissions.buildExpression(
      {
        ruleType: input.ruleType,
        roles: splitList(input.requiredRoles),
        scopes: splitList(input.requiredScopes),
        authorities: splitList(input.requiredAuthorities),
      },
      input.springMode,
    );
  }

  diagnose(input: TroubleshooterInput, signature: SignatureResult | null): DiagnosisResult {
    const ctx: Context = { input, now: this.clock.now(), causes: [], hypotheses: [] };
    const steps: DiagnosticStep[] = [];
    const push = (id: StepId, draft: StepDraft) =>
      steps.push({ id, index: steps.length + 1, title: STEP_TITLES[id], ...draft });
    const skipRest = (from: StepId, reason: string) => {
      for (const id of STEP_ORDER.slice(STEP_ORDER.indexOf(from), -1)) {
        push(id, this.skipped(reason));
      }
    };

    const decoded = this.decoder.decode(input.token);
    let mapping: AuthorityMappingResult | null = null;
    let evaluation: RuleEvaluation | null = null;
    let suggestedMapping: AuthorityMappingRule[] | null = null;

    push('structure', this.structureStep(decoded, ctx));
    if (steps[0].status === 'failed') {
      skipRest(
        'decoding',
        'Skipped — the token structure is invalid, so a server could not parse it either.',
      );
    } else {
      push('decoding', this.decodingStep(decoded, ctx));
      if (steps[1].status === 'failed') {
        skipRest('signature', 'Skipped — the header or payload could not be decoded.');
      } else {
        push('signature', this.signatureStep(decoded, signature, ctx));
        push('temporal', this.temporalStep(decoded, ctx));
        push('issuer', this.issuerStep(decoded, ctx));
        push('audience', this.audienceStep(decoded, ctx));
        const extracted = this.permissions.extract(decoded.payload);
        push('claims', this.claimsStep(decoded, extracted, ctx));
        const mapped = this.mappingStep(decoded, extracted, ctx);
        mapping = mapped.mapping;
        push('mapping', mapped.step);
        const perm = this.permissionStep(decoded, extracted, mapping, ctx);
        evaluation = perm.evaluation;
        suggestedMapping = perm.suggestedMapping;
        push('permission', perm.step);
      }
    }

    this.addHypotheses(ctx, steps);
    const causes = this.rank(ctx.causes, input);
    const mostLikely = causes.find((c) => c.confidence !== 'possible') ?? null;
    const outcome = this.outcome(causes, steps, input);
    const headline = this.headline(outcome, mostLikely, evaluation, input);
    push('final', this.finalStep(outcome, headline, mostLikely, causes, ctx.hypotheses));

    const counts = this.count(steps.filter((s) => s.id !== 'final'));
    const recommendations = [
      ...new Set([...causes, ...ctx.hypotheses].map((c) => c.recommendation)),
    ];

    return {
      analyzedAt: ctx.now,
      httpStatus: input.httpStatus,
      method: input.method,
      endpoint: input.endpoint,
      steps,
      counts,
      causes,
      hypotheses: ctx.hypotheses,
      mostLikely,
      outcome,
      headline,
      statusNote: this.statusNote(input, causes),
      recommendations,
      mapping,
      evaluation,
      signature: input.signatureMode === 'skip' ? null : signature,
      suggestedMapping,
    };
  }

  // ---------------------------------------------------------------- steps

  private structureStep(decoded: DecodedJwt, ctx: Context): StepDraft {
    const analyzed =
      'Checks that the input is a compact JWS: three Base64URL segments separated by dots, within size limits, and not an encrypted JWE.';
    const data: StepDatum[] = [
      { label: 'Segments', value: String(decoded.segmentCount) },
      { label: 'Length', value: `${decoded.token.length} characters` },
      { label: 'Detected type', value: decoded.kind.toUpperCase() },
    ];
    const structural = decoded.issues.filter((i) => i.segment === 'token');
    const errors = structural.filter((i) => i.severity === 'error');
    if (decoded.kind === 'empty') {
      this.cause(
        ctx,
        'token-missing',
        'Token Missing',
        'authentication',
        'confirmed',
        'structure',
        'No token was provided for analysis.',
        ['The token field is empty.'],
        'Make sure the client sends "Authorization: Bearer <access_token>" on every request to the protected endpoint.',
      );
      return {
        status: 'failed',
        summary: 'No token provided',
        analyzed,
        data,
        evidence: ['The token input is empty.'],
        impact:
          'Without a bearer token Spring Security answers HTTP 401 with WWW-Authenticate: Bearer.',
        explanation:
          'BearerTokenAuthenticationFilter only authenticates requests carrying a bearer token. Missing tokens leave the request anonymous, and protected endpoints return 401.',
        recommendations: [
          'Send the access token in the Authorization header using the Bearer scheme.',
        ],
      };
    }
    if (errors.length) {
      const evidence = errors.map((e) => e.message);
      this.cause(
        ctx,
        'malformed-token',
        decoded.kind === 'jwe' ? 'Encrypted Token (JWE) Received' : 'Malformed Token',
        'authentication',
        'confirmed',
        'structure',
        errors[0].message,
        evidence,
        decoded.kind === 'jwe'
          ? 'Resource servers configured for signed JWTs cannot read JWE tokens. Request a signed access token (JWS) or configure decryption.'
          : 'Send the full compact token (header.payload.signature) without truncation or extra characters.',
      );
      return {
        status: 'failed',
        summary: errors[0].message,
        analyzed,
        data,
        evidence,
        impact:
          'The JwtDecoder cannot parse the token and the request is rejected with HTTP 401 (invalid_token).',
        explanation:
          'A compact JWS is BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature). Any other shape fails parsing before any claim is evaluated.',
        recommendations: [
          'Copy the token directly from the Authorization header of the failing request.',
          'Check for truncation by logs, proxies or copy/paste.',
        ],
      };
    }
    const warnings = structural.filter((i) => i.severity !== 'error');
    const whitespace = warnings.find((w) => w.code === 'whitespace');
    if (whitespace) {
      this.cause(
        ctx,
        'token-whitespace',
        'Whitespace Inside Token',
        'authentication',
        'likely',
        'structure',
        whitespace.message,
        [whitespace.message],
        'Ensure the client sends the token as a single line without spaces or line breaks.',
      );
    }
    return {
      status: whitespace ? 'warning' : 'passed',
      summary: whitespace
        ? 'Valid after normalization — whitespace found'
        : 'Three Base64URL segments (JWS)',
      analyzed,
      data,
      evidence: warnings.length
        ? warnings.map((w) => w.message)
        : ['Header, payload and signature segments present.'],
      impact: whitespace
        ? 'Servers do not strip whitespace inside tokens; this would cause a 401.'
        : null,
      explanation:
        'The token has the compact JWS serialization expected by OAuth 2.0 resource servers.',
      recommendations: [],
    };
  }

  private decodingStep(decoded: DecodedJwt, ctx: Context): StepDraft {
    const analyzed =
      'Decodes header and payload from Base64URL to UTF-8 JSON objects and validates registered claim types (exp, nbf, iat, iss, aud…).';
    const errors = decoded.issues.filter((i) => i.severity === 'error' && i.segment !== 'token');
    const warnings = decoded.issues.filter(
      (i) => i.severity === 'warning' && i.segment !== 'token',
    );
    const data: StepDatum[] = [
      { label: 'Algorithm (alg)', value: decoded.alg ?? '—' },
      { label: 'Type (typ)', value: String(decoded.header?.['typ'] ?? '—') },
      { label: 'Key ID (kid)', value: String(decoded.header?.['kid'] ?? '—') },
      { label: 'Claims', value: decoded.payload ? Object.keys(decoded.payload).join(', ') : '—' },
    ];
    if (errors.length) {
      const evidence = errors.map((e) => `${e.segment}: ${e.message}`);
      const decodeFailure = !decoded.decoded;
      this.cause(
        ctx,
        decodeFailure ? 'malformed-token' : 'invalid-claim-types',
        decodeFailure ? 'Malformed Token' : 'Invalid Claim Types',
        'authentication',
        'confirmed',
        'decoding',
        errors[0].message,
        evidence,
        decodeFailure
          ? 'Regenerate the token with a compliant JWT library.'
          : 'Fix the issuer so that registered claims use the types defined in RFC 7519 (e.g. exp as a number of seconds).',
      );
      return {
        status: 'failed',
        summary: errors[0].message,
        analyzed,
        data,
        evidence,
        impact:
          'Nimbus JOSE + JWT (used by Spring Security) rejects tokens whose header/payload are not valid JSON or whose registered claims have invalid types — HTTP 401.',
        explanation:
          'JWT libraries parse claims strictly. For example, an "exp" string instead of a NumericDate makes the token invalid.',
        recommendations: ['Inspect the token in the JWT Inspector for the exact failing segment.'],
      };
    }
    return {
      status: warnings.length ? 'warning' : 'passed',
      summary: warnings.length
        ? warnings[0].message
        : `Header and payload decoded (${Object.keys(decoded.payload ?? {}).length} claims)`,
      analyzed,
      data,
      evidence: warnings.length
        ? warnings.map((w) => w.message)
        : ['Header and payload are valid JSON objects with correctly typed registered claims.'],
      impact: null,
      explanation:
        'Decoding only reveals the content. Anyone can decode a JWT — authenticity requires signature verification.',
      recommendations: [],
    };
  }

  private signatureStep(
    decoded: DecodedJwt,
    signature: SignatureResult | null,
    ctx: Context,
  ): StepDraft {
    const { input } = ctx;
    const alg = decoded.alg ?? '';
    const analyzed =
      'Uses a cryptographic verification executed in TokenScope (Web Crypto API) with a key you provided. Decoding never counts as verification.';
    const data: StepDatum[] = [
      { label: 'Algorithm', value: alg || '—' },
      {
        label: 'Mode',
        value:
          input.signatureMode === 'skip'
            ? 'Not requested'
            : input.signatureMode === 'use-verifier'
              ? 'Signature Verifier result'
              : 'Verified during diagnosis',
      },
    ];
    if (alg.toLowerCase() === 'none') {
      this.cause(
        ctx,
        'alg-none',
        'Unsigned Token (alg: none)',
        'authentication',
        'confirmed',
        'signature',
        'The token declares alg "none" and carries no signature.',
        ['Header: {"alg":"none"}'],
        'Never accept unsigned tokens. Obtain a token signed by the authorization server.',
      );
      return {
        status: 'failed',
        summary: 'alg "none" — token is unsigned',
        analyzed,
        data,
        evidence: ['The header declares alg "none".'],
        impact: 'Spring Security (Nimbus) rejects unsigned tokens — HTTP 401.',
        explanation: 'An unsigned JWT can be forged by anyone. Resource servers must reject it.',
        recommendations: ['Check the authorization server configuration and the token source.'],
      };
    }
    if (!ALGORITHMS[alg]) {
      this.cause(
        ctx,
        'unsupported-alg',
        'Unsupported Algorithm',
        'authentication',
        'likely',
        'signature',
        `Algorithm "${alg}" is not a standard JWS signing algorithm supported by common resource servers.`,
        [`alg = "${alg}"`],
        'Configure the issuer to sign with an algorithm accepted by the resource server (e.g. RS256), or configure the JwtDecoder accordingly.',
      );
      return {
        status: 'warning',
        summary: `Algorithm "${alg}" is not supported`,
        analyzed,
        data,
        evidence: [`alg = "${alg}"`],
        impact:
          'If the server does not accept this algorithm, the token is rejected with HTTP 401.',
        explanation:
          'NimbusJwtDecoder accepts only the algorithms configured for its key source (RS256 by default for JWK Set URIs).',
        recommendations: [],
      };
    }
    if (input.signatureMode === 'skip' || !signature) {
      const why =
        input.signatureMode === 'use-verifier'
          ? 'No Signature Verifier result exists for this exact token.'
          : 'Signature verification was not requested.';
      return {
        status: 'not-verified',
        summary: 'Signature was not verified',
        analyzed,
        data,
        evidence: [
          why,
          `The ${alg} signature (${decoded.signatureLength} bytes) is present but its authenticity is unknown.`,
        ],
        impact:
          'An invalid signature or a key mismatch cannot be ruled out. A server would reject such a token with HTTP 401.',
        explanation:
          'TokenScope never treats a decodable token as authentic. Provide the secret or public key (or use the Signature Verifier) to check it.',
        recommendations: ['Verify the signature with the issuer key (secret, PEM, JWK or JWKS).'],
      };
    }
    data.push({ label: 'Key', value: signature.keyDescription ?? '—' });
    switch (signature.status) {
      case 'verified':
        return {
          status: 'passed',
          summary: 'Signature verified with the provided key',
          analyzed,
          data,
          evidence: [signature.message, ...signature.warnings],
          impact: null,
          explanation:
            'The header and payload were not modified since they were signed by the holder of this key. The server must also trust the same key.',
          recommendations: [],
        };
      case 'invalid':
        this.cause(
          ctx,
          'invalid-signature',
          'Invalid Signature',
          'authentication',
          'confirmed',
          'signature',
          signature.message,
          [signature.message, ...signature.details],
          'Make sure the token was not modified and that the server verifies it with the key that signed it (check kid and JWKS rotation).',
        );
        return {
          status: 'failed',
          summary: signature.title,
          analyzed,
          data,
          evidence: [signature.message, ...signature.details],
          impact:
            'Spring Security rejects tokens with invalid signatures — HTTP 401 with error="invalid_token".',
          explanation:
            'The signature does not match the header and payload for the provided key. Either the token was tampered with, or it was signed by a different key.',
          recommendations: [
            'Re-issue the token; never edit JWT payloads manually.',
            'Compare the token kid with the keys published in the JWKS.',
          ],
        };
      default: {
        const kidMissing = /No key with kid/.test(signature.message);
        this.cause(
          ctx,
          kidMissing ? 'kid-not-found' : 'signature-key-issue',
          kidMissing ? 'Signing Key Not Found (kid)' : 'Signature Could Not Be Verified',
          'authentication',
          kidMissing ? 'likely' : 'possible',
          'signature',
          signature.message,
          [signature.message],
          kidMissing
            ? 'Check key rotation: the server JWKS must contain the kid used to sign the token.'
            : 'Provide a key compatible with the token algorithm and retry the verification.',
        );
        return {
          status: 'warning',
          summary: signature.title,
          analyzed,
          data,
          evidence: [signature.message, ...signature.warnings],
          impact: 'If the server faces the same key problem, it rejects the token with HTTP 401.',
          explanation: 'The verification could not be completed with the provided key.',
          recommendations: [],
        };
      }
    }
  }

  private temporalStep(decoded: DecodedJwt, ctx: Context): StepDraft {
    const { input, now } = ctx;
    const t = this.timeline.compute(decoded.payload, now, input.clockSkewSeconds);
    const fmt = (ms: number | null) => (ms === null ? 'not present' : formatDateTime(ms, 'utc'));
    const analyzed = `Compares exp, nbf and iat with the current time using a clock skew of ${t.skewSeconds}s (Spring's JwtTimestampValidator default is 60s).`;
    const data: StepDatum[] = [
      { label: 'Issued at (iat)', value: fmt(t.iat) },
      { label: 'Not before (nbf)', value: fmt(t.nbf) },
      { label: 'Expiration (exp)', value: fmt(t.exp) },
      { label: 'Current time', value: fmt(now) },
      { label: 'Clock skew', value: `${t.skewSeconds}s` },
    ];
    switch (t.state) {
      case 'expired': {
        const ago = formatDuration((now - (t.exp ?? now)) / 1000);
        const evidence = [
          `Expiration: ${toIso(t.exp!)}`,
          `Current time: ${toIso(now)}`,
          `Expired ${ago} ago (skew ${t.skewSeconds}s already applied).`,
        ];
        this.cause(
          ctx,
          'token-expired',
          'JWT Expired',
          'authentication',
          'confirmed',
          'temporal',
          `The token expired ${ago} ago.`,
          evidence,
          'Obtain a new access token using the configured authentication flow (e.g. refresh token grant) and retry the request.',
        );
        return {
          status: 'failed',
          summary: `Expired ${ago} ago`,
          analyzed,
          data,
          evidence,
          impact:
            'Spring Security rejects expired tokens — HTTP 401 with error_description "Jwt expired at …".',
          explanation:
            'RFC 7519 requires the current time to be before "exp". JwtTimestampValidator allows only the configured clock skew.',
          recommendations: [
            'Implement automatic token refresh before expiration.',
            'Check whether the client caches tokens beyond their lifetime.',
          ],
        };
      }
      case 'not-yet-valid': {
        const evidence = [
          `Not before: ${toIso(t.nbf!)}`,
          `Current time: ${toIso(now)}`,
          `Valid in ${formatDuration((t.nbf! - now) / 1000)} (skew ${t.skewSeconds}s applied).`,
        ];
        this.cause(
          ctx,
          'token-not-yet-valid',
          'Token Not Yet Valid',
          'authentication',
          'confirmed',
          'temporal',
          'The current time is before the "nbf" claim.',
          evidence,
          'Synchronize clocks (NTP) between the authorization server and the resource server, or increase the allowed clock skew.',
        );
        return {
          status: 'failed',
          summary: 'Token is not valid yet (nbf in the future)',
          analyzed,
          data,
          evidence,
          impact: 'Spring Security rejects the token — HTTP 401 with "Jwt used before …".',
          explanation:
            'A token must not be accepted before "nbf". This usually indicates clock drift between servers.',
          recommendations: ['Check server clocks (NTP).'],
        };
      }
      case 'invalid': {
        this.cause(
          ctx,
          'invalid-temporal-claims',
          'Invalid Temporal Claims',
          'authentication',
          'confirmed',
          'temporal',
          t.issues[0],
          t.issues,
          'Fix the issuer so that iat ≤ nbf < exp and all are NumericDates in seconds.',
        );
        return {
          status: 'failed',
          summary: t.issues[0],
          analyzed,
          data,
          evidence: t.issues,
          impact: 'Tokens with inconsistent time claims are rejected or behave unpredictably.',
          explanation:
            'Temporal claims must be NumericDates (seconds) and form a consistent window.',
          recommendations: [],
        };
      }
      case 'missing-exp':
        this.hypothesis(
          ctx,
          'missing-exp',
          'Token Without Expiration',
          'authentication',
          'temporal',
          'The token has no "exp" claim.',
          ['"exp" is absent.'],
          'Issue tokens with a short "exp". Some resource servers and gateways require it.',
        );
        return {
          status: 'warning',
          summary: 'No expiration (exp) claim',
          analyzed,
          data,
          evidence: ['The token never expires by itself.', ...t.issues],
          impact:
            "Spring's JwtTimestampValidator accepts tokens without exp, but other gateways or custom validators may reject them.",
          explanation: 'Tokens without expiration remain valid forever if leaked.',
          recommendations: ['Add an "exp" claim with a short lifetime.'],
        };
      default: {
        const remaining = t.remainingSeconds ?? 0;
        const soon = remaining < 60;
        const evidence = [
          `Expires at ${toIso(t.exp!)} — ${formatDuration(remaining)} remaining.`,
          ...t.issues,
        ];
        if (soon)
          this.hypothesis(
            ctx,
            'about-to-expire',
            'Token About to Expire',
            'authentication',
            'temporal',
            'The token expires in less than a minute.',
            evidence,
            'Refresh tokens slightly before expiration to avoid race conditions.',
          );
        return {
          status: soon || t.issues.length ? 'warning' : 'passed',
          summary: `Within validity window — ${formatDuration(remaining)} remaining`,
          analyzed,
          data,
          evidence,
          impact: null,
          explanation:
            'Temporal validity does not imply cryptographic validity; it only means the time claims accept the current instant.',
          recommendations: [],
        };
      }
    }
  }

  private issuerStep(decoded: DecodedJwt, ctx: Context): StepDraft {
    const expected = ctx.input.expectedIssuer.trim();
    const actual = decoded.payload?.['iss'];
    const analyzed =
      'Compares the "iss" claim with the expected issuer (spring.security.oauth2.resourceserver.jwt.issuer-uri). Spring compares the strings exactly.';
    const data: StepDatum[] = [
      { label: 'Expected', value: expected || 'Not configured' },
      { label: 'Token iss', value: typeof actual === 'string' ? actual : 'not present' },
    ];
    if (!expected) {
      return {
        status: 'not-applicable',
        summary: 'No expected issuer configured',
        analyzed,
        data,
        evidence: ['Fill "Expected Issuer" to validate it.'],
        impact: null,
        explanation: 'Without an expected value TokenScope cannot evaluate this check.',
        recommendations: [],
      };
    }
    if (typeof actual !== 'string') {
      this.cause(
        ctx,
        'issuer-missing',
        'Issuer Claim Missing',
        'authentication',
        'confirmed',
        'issuer',
        'The token has no "iss" claim but an issuer is expected.',
        ['"iss" is absent.'],
        'Issue tokens with the "iss" claim, or review the issuer validation configured on the server.',
      );
      return {
        status: 'failed',
        summary: 'Token has no iss claim',
        analyzed,
        data,
        evidence: ['"iss" is absent.'],
        impact: 'JwtIssuerValidator rejects tokens without the expected issuer — HTTP 401.',
        explanation: 'When issuer-uri is configured, Spring requires an exact iss match.',
        recommendations: [],
      };
    }
    if (actual === expected) {
      return {
        status: 'passed',
        summary: 'Issuer matches',
        analyzed,
        data,
        evidence: [`iss = "${actual}"`],
        impact: null,
        explanation:
          'The token was issued by the expected authorization server (by claim — the signature step proves who signed it).',
        recommendations: [],
      };
    }
    const hint = this.stringHint(actual, expected);
    const evidence = [`Expected: "${expected}"`, `Found: "${actual}"`, ...(hint ? [hint] : [])];
    this.cause(
      ctx,
      'issuer-mismatch',
      'Issuer Mismatch',
      'authentication',
      'confirmed',
      'issuer',
      `The token issuer "${actual}" differs from the expected "${expected}".`,
      evidence,
      'Align spring.security.oauth2.resourceserver.jwt.issuer-uri with the "iss" emitted by the authorization server (watch trailing slashes, scheme, host and realm).',
    );
    return {
      status: 'failed',
      summary: 'Issuer does not match',
      analyzed,
      data,
      evidence,
      impact: 'Spring Security rejects the token with HTTP 401 ("The iss claim is not valid").',
      explanation:
        'Issuer validation is an exact string comparison. Tokens from another realm, environment or host fail.',
      recommendations: [
        'Check whether the token comes from another environment (dev/staging/prod) or realm.',
      ],
    };
  }

  private audienceStep(decoded: DecodedJwt, ctx: Context): StepDraft {
    const expected = splitList(ctx.input.expectedAudience);
    const actual = this.claims.audiences(decoded.payload);
    const analyzed =
      'Checks that "aud" contains the expected audience (spring.security.oauth2.resourceserver.jwt.audiences).';
    const data: StepDatum[] = [
      { label: 'Expected', value: expected.join(', ') || 'Not configured' },
      { label: 'Token aud', value: actual.join(', ') || 'not present' },
    ];
    if (expected.length === 0) {
      return {
        status: 'not-applicable',
        summary: 'No expected audience configured',
        analyzed,
        data,
        evidence: ['Spring Boot validates the audience only when "audiences" is configured.'],
        impact: null,
        explanation: 'Without an expected value TokenScope cannot evaluate this check.',
        recommendations: [],
      };
    }
    if (actual.length === 0) {
      this.cause(
        ctx,
        'audience-missing',
        'Audience Claim Missing',
        'authentication',
        'confirmed',
        'audience',
        'The token has no "aud" claim but an audience is expected.',
        ['"aud" is absent.'],
        'Request the token for the correct audience/resource (e.g. "audience" or "resource" parameter) or adjust the server audience validation.',
      );
      return {
        status: 'failed',
        summary: 'Token has no aud claim',
        analyzed,
        data,
        evidence: ['"aud" is absent.'],
        impact: 'Audience validation fails — HTTP 401.',
        explanation: 'A token without audience is not bound to any API.',
        recommendations: [],
      };
    }
    const matched = expected.filter((e) => actual.includes(e));
    if (matched.length) {
      return {
        status: 'passed',
        summary: `Audience contains "${matched[0]}"`,
        analyzed,
        data,
        evidence: [`aud = ${JSON.stringify(actual)}`],
        impact: null,
        explanation: 'The token is intended for this API.',
        recommendations: [],
      };
    }
    const hints = expected
      .flatMap((e) => actual.map((a) => this.stringHint(a, e)))
      .filter((h): h is string => !!h);
    const evidence = [
      `Expected one of: ${expected.join(', ')}`,
      `Found: ${actual.join(', ')}`,
      ...hints,
    ];
    this.cause(
      ctx,
      'audience-mismatch',
      'Audience Mismatch',
      'authentication',
      'confirmed',
      'audience',
      `The token audience (${actual.join(', ')}) does not include ${expected.join(' / ')}.`,
      evidence,
      'Request a token for this API audience, or add the audience to the resource server configuration.',
    );
    return {
      status: 'failed',
      summary: 'Audience does not match',
      analyzed,
      data,
      evidence,
      impact: 'Spring Security rejects the token with HTTP 401 ("The aud claim is not valid").',
      explanation:
        'Tokens issued for another API must not be accepted (confused deputy protection).',
      recommendations: [],
    };
  }

  private claimsStep(
    decoded: DecodedJwt,
    extracted: ExtractedPermissions,
    ctx: Context,
  ): StepDraft {
    const analyzed =
      'Looks for permission claims: roles, authorities, scope, scp, groups, permissions, realm_access.roles and resource_access.*.roles.';
    const data: StepDatum[] = [
      {
        label: 'Subject (sub)',
        value:
          typeof decoded.payload?.['sub'] === 'string'
            ? (decoded.payload['sub'] as string)
            : 'not present',
      },
      ...extracted.matches.map((m) => ({
        label: `${m.path} (${m.kind})`,
        value: m.values.join(', '),
      })),
    ];
    const hasRequirement = !!this.requirementExpression(ctx.input);
    if (extracted.matches.length === 0) {
      if (hasRequirement) {
        this.cause(
          ctx,
          'no-permission-claims',
          'No Permission Claims in Token',
          'authorization',
          'likely',
          'claims',
          'The token carries no roles, scopes or authorities.',
          ['No roles/authorities/scope/scp claims found.'],
          'Configure the authorization server to include roles or scopes in the access token (client scopes / mappers).',
        );
      }
      return {
        status: hasRequirement ? 'warning' : 'passed',
        summary: 'No permission claims found',
        analyzed,
        data,
        evidence: ['None of the known permission claims are present.'],
        impact: hasRequirement
          ? 'Authorization rules requiring roles or scopes will deny access — HTTP 403.'
          : null,
        explanation:
          'Access tokens usually carry scopes (OAuth 2.0) and/or roles (custom claims, Keycloak realm_access).',
        recommendations: [],
      };
    }
    return {
      status: 'passed',
      summary: `Found ${extracted.matches.map((m) => m.path).join(', ')}`,
      analyzed,
      data,
      evidence: extracted.matches.map((m) => `${m.path}: ${m.values.join(', ')}`),
      impact: null,
      explanation:
        'These raw values are only useful if the server maps them to GrantedAuthorities — see the next step.',
      recommendations: [],
    };
  }

  private mappingStep(
    decoded: DecodedJwt,
    extracted: ExtractedPermissions,
    ctx: Context,
  ): { step: StepDraft; mapping: AuthorityMappingResult } {
    const { input } = ctx;
    if (!input.springMode) {
      const authorities = [
        ...new Set([...extracted.roles, ...extracted.scopes, ...extracted.authorities]),
      ];
      return {
        mapping: { authorities, traces: [] },
        step: {
          status: 'passed',
          summary: `Generic mode — ${authorities.length} raw value(s) used as permissions`,
          analyzed:
            'Generic mode: raw claim values are used as permissions and compared ignoring ROLE_/SCOPE_ prefixes and case.',
          data: [{ label: 'Permissions', value: authorities.join(', ') || 'none' }],
          evidence: authorities.length
            ? [`Values: ${authorities.join(', ')}`]
            : ['No values found.'],
          impact: null,
          explanation:
            'Enable Spring Security Mode for an exact simulation of JwtGrantedAuthoritiesConverter (prefixes are significant there).',
          recommendations: [],
        },
      };
    }
    const mapping = this.permissions.mapAuthorities(decoded.payload, input.mappingRules);
    const usedPaths = new Set(mapping.traces.map((t) => t.claimUsed).filter(Boolean));
    const unmapped = extracted.matches.filter(
      (m) => !usedPaths.has(m.path) && !(m.path === 'scp' && usedPaths.has('scope')),
    );
    const evidence = [
      ...mapping.traces.map(
        (t) =>
          `${t.rule.claim} → prefix "${t.rule.prefix}": ${t.note}${t.mapped.length ? ` Result: ${t.mapped.join(', ')}` : ''}`,
      ),
      ...unmapped.map(
        (m) =>
          `Claim "${m.path}" (${m.values.join(', ')}) is present but NOT mapped by any converter.`,
      ),
    ];
    const status: StepStatus =
      input.mappingRules.length === 0 || mapping.authorities.length === 0 || unmapped.length
        ? 'warning'
        : 'passed';
    return {
      mapping,
      step: {
        status,
        summary: mapping.authorities.length
          ? `Granted authorities: ${mapping.authorities.join(', ')}`
          : 'No authorities produced by the configured mapping',
        analyzed:
          'Simulates JwtGrantedAuthoritiesConverter → JwtAuthenticationConverter with the configured claim(s), prefix and delimiter.',
        data: [
          ...mapping.traces.map((t) => ({
            label: `${t.rule.claim} (prefix "${t.rule.prefix}")`,
            value: t.mapped.join(', ') || '—',
          })),
          { label: 'Authorities', value: mapping.authorities.join(', ') || 'none' },
        ],
        evidence,
        impact: unmapped.length
          ? 'Values in unmapped claims are invisible to hasRole/hasAuthority rules.'
          : null,
        explanation:
          'By default Spring Security maps only "scope"/"scp" into SCOPE_* authorities. Roles in custom claims require a custom JwtGrantedAuthoritiesConverter.',
        recommendations: unmapped.length
          ? [
              `Map the claim "${unmapped[0].path}" with a JwtGrantedAuthoritiesConverter if the server relies on it.`,
            ]
          : [],
      },
    };
  }

  private permissionStep(
    decoded: DecodedJwt,
    extracted: ExtractedPermissions,
    mapping: AuthorityMappingResult,
    ctx: Context,
  ): {
    step: StepDraft;
    evaluation: RuleEvaluation | null;
    suggestedMapping: AuthorityMappingRule[] | null;
  } {
    const { input } = ctx;
    const expression = this.requirementExpression(input);
    const analyzed = `Evaluates the endpoint rule for ${input.method} ${input.endpoint || '(endpoint not informed)'} against the ${input.springMode ? 'mapped authorities (exact, case-sensitive)' : 'raw permissions (prefix/case-insensitive)'}.`;
    if (!expression) {
      return {
        evaluation: null,
        suggestedMapping: null,
        step: {
          status: 'not-applicable',
          summary: 'No required role, scope or authority configured',
          analyzed,
          data: [],
          evidence: [
            'Fill Required Role / Scope / Authority or a custom expression to simulate authorization.',
          ],
          impact: null,
          explanation: 'Authorization cannot be simulated without the rule the endpoint enforces.',
          recommendations: [],
        },
      };
    }
    const evaluation = this.permissions.evaluate(
      expression,
      mapping.authorities,
      input.springMode ? 'spring' : 'lenient',
    );
    const data: StepDatum[] = [
      { label: 'Rule', value: expression },
      { label: 'Authorities', value: mapping.authorities.join(', ') || 'none' },
    ];
    if (!evaluation.parsed) {
      this.cause(
        ctx,
        'invalid-rule',
        'Invalid Rule Expression',
        'configuration',
        'confirmed',
        'permission',
        evaluation.parseError ?? 'The rule could not be parsed.',
        [evaluation.parseError ?? ''],
        "Use a supported expression, e.g. hasRole('ADMIN') or hasAuthority('SCOPE_read').",
      );
      return {
        evaluation,
        suggestedMapping: null,
        step: {
          status: 'warning',
          summary: `Rule could not be parsed: ${evaluation.parseError}`,
          analyzed,
          data,
          evidence: [evaluation.parseError ?? ''],
          impact: null,
          explanation:
            'TokenScope parses a safe subset of Spring Security expressions without executing code.',
          recommendations: [],
        },
      };
    }
    const evidence = [
      ...evaluation.checks.map(
        (c) =>
          `${c.expression} → ${c.result ? 'satisfied' : 'NOT satisfied'}${c.matched.length ? ` (matched ${c.matched.join(', ')})` : ''}${c.missing.length && !c.result ? ` (missing ${c.missing.join(', ')})` : ''}`,
      ),
      ...evaluation.warnings,
    ];
    if (evaluation.granted) {
      return {
        evaluation,
        suggestedMapping: null,
        step: {
          status: evaluation.warnings.length ? 'warning' : 'passed',
          summary: 'Access Granted — Simulated',
          analyzed,
          data,
          evidence,
          impact: null,
          explanation:
            'The simulated authorities satisfy the configured rule. The real server may still apply other rules (method security, CSRF, filters).',
          recommendations: [],
        },
      };
    }

    // Classify why access was denied.
    let suggestedMapping: AuthorityMappingRule[] | null = null;
    const missing = [
      ...new Set(evaluation.checks.filter((c) => !c.result).flatMap((c) => c.missing)),
    ];
    const nearMatches = evaluation.checks.flatMap((c) => c.nearMatches);
    const handled = new Set<string>();
    for (const near of nearMatches) {
      if (handled.has(near.required)) continue;
      handled.add(near.required);
      const ev = [`Required: ${near.required}`, `Token authority: ${near.found}`];
      if (near.reason === 'role-prefix') {
        this.cause(
          ctx,
          'role-prefix-mismatch',
          'ROLE_ Prefix Mismatch',
          'authorization',
          'confirmed',
          'permission',
          `The rule requires "${near.required}" but the token provides "${near.found}" — they differ only by the ROLE_ prefix.`,
          ev,
          near.required.startsWith('ROLE_')
            ? 'Set JwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_") for the roles claim, or change the rule to hasAuthority(\'' +
                near.found +
                "')."
            : `Use hasRole('${stripPrefix(near.found)}') or hasAuthority('${near.found}') so the prefix matches.`,
        );
      } else if (near.reason === 'scope-prefix') {
        this.cause(
          ctx,
          'scope-prefix-mismatch',
          'SCOPE_ Prefix Mismatch',
          'authorization',
          'confirmed',
          'permission',
          `The rule requires "${near.required}" but the token provides "${near.found}" — they differ only by the SCOPE_ prefix.`,
          ev,
          near.required.startsWith('SCOPE_')
            ? 'Keep the default SCOPE_ prefix for scope claims, or require the authority exactly as mapped.'
            : `Spring maps scopes to "SCOPE_<scope>": use hasAuthority('${near.found}').`,
        );
      } else if (near.reason === 'case') {
        this.cause(
          ctx,
          'authority-case-mismatch',
          'Authority Case Mismatch',
          'authorization',
          'confirmed',
          'permission',
          `"${near.required}" and "${near.found}" differ only by letter case. Spring compares authorities case-sensitively.`,
          ev,
          'Normalize the case of roles in the issuer or in the rule.',
        );
      } else {
        this.cause(
          ctx,
          'authority-prefix-mismatch',
          'Authority Prefix Mismatch',
          'authorization',
          'confirmed',
          'permission',
          `"${near.required}" and "${near.found}" refer to the same name with different prefixes.`,
          ev,
          'Align the authority prefix configured in JwtGrantedAuthoritiesConverter with the endpoint rule.',
        );
      }
    }

    for (const required of missing.filter((m) => !handled.has(m))) {
      const name = stripPrefix(required);
      // A matching raw value exists in a claim the converter does not read.
      const unmappedClaim = input.springMode
        ? extracted.matches.find(
            (m) =>
              m.values.some((v) => stripPrefix(v).toLowerCase() === name.toLowerCase()) &&
              !mapping.traces.some((t) => t.claimUsed === m.path),
          )
        : undefined;
      if (unmappedClaim) {
        handled.add(required);
        const prefix = required.startsWith('ROLE_')
          ? 'ROLE_'
          : required.startsWith('SCOPE_')
            ? 'SCOPE_'
            : '';
        const rawValue = unmappedClaim.values.find(
          (v) => stripPrefix(v).toLowerCase() === name.toLowerCase(),
        )!;
        const effectivePrefix = rawValue.startsWith(prefix) ? '' : prefix;
        suggestedMapping = [
          ...input.mappingRules,
          { claim: unmappedClaim.path, prefix: effectivePrefix, delimiter: ' ' },
        ];
        this.cause(
          ctx,
          'claim-not-mapped',
          'Permission Claim Not Mapped',
          'authorization',
          'confirmed',
          'permission',
          `The token contains "${rawValue}" in "${unmappedClaim.path}", but the configured converter does not read that claim, so "${required}" is never granted.`,
          [
            `Claim ${unmappedClaim.path}: ${JSON.stringify(unmappedClaim.values)}`,
            `Mapped authorities: ${mapping.authorities.join(', ') || 'none'}`,
            `Required: ${required}`,
          ],
          `Configure a JwtGrantedAuthoritiesConverter with setAuthoritiesClaimName("${unmappedClaim.path}") and setAuthorityPrefix("${effectivePrefix}").`,
        );
      }
    }

    const remaining = missing.filter((m) => !handled.has(m));
    if (remaining.length) {
      const roles = remaining.filter((r) => r.startsWith('ROLE_'));
      const scopes = remaining.filter((r) => r.startsWith('SCOPE_'));
      const others = remaining.filter((r) => !r.startsWith('ROLE_') && !r.startsWith('SCOPE_'));
      const tokenAuth = `Token authorities: ${mapping.authorities.join(', ') || 'none'}`;
      if (roles.length) {
        this.cause(
          ctx,
          'missing-role',
          'Missing Required Authority',
          'authorization',
          'confirmed',
          'permission',
          `Token contains ${mapping.authorities.filter((a) => a.startsWith('ROLE_')).join(', ') || 'no roles'}, but the simulated endpoint rule requires ${roles.join(' / ')}.`,
          [`Required: ${roles.join(', ')}`, tokenAuth],
          'Verify the authority mapping and endpoint authorization configuration, or grant the role to the user in the identity provider.',
        );
      }
      if (scopes.length) {
        this.cause(
          ctx,
          'missing-scope',
          'Insufficient Scope',
          'authorization',
          'confirmed',
          'permission',
          `The token scopes do not include ${scopes.map((s) => s.slice(6)).join(' / ')} (required ${scopes.join(', ')}).`,
          [`Required: ${scopes.join(', ')}`, tokenAuth],
          'Request the missing scope during authorization (scope parameter) and make sure the client is allowed to obtain it.',
        );
      }
      if (others.length) {
        this.cause(
          ctx,
          'missing-authority',
          'Missing Required Authority',
          'authorization',
          'confirmed',
          'permission',
          `The token does not contain the required authority ${others.join(' / ')}.`,
          [`Required: ${others.join(', ')}`, tokenAuth],
          'Verify the authority mapping and endpoint authorization configuration.',
        );
      }
    }

    return {
      evaluation,
      suggestedMapping,
      step: {
        status: 'failed',
        summary: 'Access Denied — Simulated',
        analyzed,
        data,
        evidence,
        impact:
          'With these authorities Spring Security AuthorizationFilter denies access — HTTP 403 (AccessDeniedException).',
        explanation: input.springMode
          ? 'hasRole(\'X\') checks the authority "ROLE_X"; hasAuthority(\'X\') checks "X" exactly. Scopes become "SCOPE_<scope>" by default.'
          : 'In generic mode permissions are compared without prefixes and case-insensitively.',
        recommendations: ['Compare the required authority with the mapped authorities above.'],
      },
    };
  }

  private finalStep(
    outcome: LocalOutcome,
    headline: DiagnosisHeadline,
    mostLikely: DiagnosisCause | null,
    causes: DiagnosisCause[],
    hypotheses: DiagnosisCause[],
  ): StepDraft {
    const status: StepStatus =
      outcome === 'authentication-failure' || outcome === 'authorization-failure'
        ? 'failed'
        : outcome === 'insufficient-information'
          ? 'not-verified'
          : causes.length || hypotheses.length
            ? 'warning'
            : 'passed';
    return {
      status,
      summary: headline.title,
      analyzed:
        'Ranks the collected causes by confidence (confirmed → likely → possible) and relevance to the reported HTTP status.',
      data: [
        {
          label: 'Confirmed causes',
          value: String(causes.filter((c) => c.confidence === 'confirmed').length),
        },
        {
          label: 'Likely causes',
          value: String(causes.filter((c) => c.confidence === 'likely').length),
        },
        { label: 'Hypotheses', value: String(hypotheses.length) },
      ],
      evidence: mostLikely ? mostLikely.evidence : [headline.description],
      impact: null,
      explanation:
        'The diagnosis reflects only the token and the rules you configured. TokenScope has no access to the real server configuration and never asserts its decision.',
      recommendations: mostLikely ? [mostLikely.recommendation] : [],
    };
  }

  // ---------------------------------------------------------------- conclusions

  private addHypotheses(ctx: Context, steps: DiagnosticStep[]): void {
    const { input } = ctx;
    const status = (id: StepId) => steps.find((s) => s.id === id)?.status;
    const confirmedAuth = ctx.causes.some(
      (c) => c.category === 'authentication' && c.confidence !== 'possible',
    );
    const confirmedAuthz = ctx.causes.some(
      (c) => c.category === 'authorization' && c.confidence !== 'possible',
    );

    if (input.httpStatus !== '403' && !confirmedAuth && status('signature') === 'not-verified') {
      this.hypothesis(
        ctx,
        'signature-unverified',
        'Signature or Key Mismatch Not Ruled Out',
        'authentication',
        'signature',
        'The signature was not verified, so a tampered token or a key mismatch (kid rotation, wrong JWKS, wrong secret) remains possible.',
        ['Signature Verification: Not Verified'],
        'Verify the signature with the key the server uses (JWKS URI or secret).',
      );
    }
    if (input.httpStatus === '401' && !confirmedAuth) {
      this.hypothesis(
        ctx,
        'token-not-sent',
        'Token Not Sent or Malformed Header',
        'authentication',
        'structure',
        'The local token looks acceptable. The request may not carry it (missing Authorization header, wrong scheme, stripped by a proxy or CORS preflight).',
        ['All local authentication checks passed or were not applicable.'],
        'Inspect the actual request: "Authorization: Bearer <token>" must be present and reach the API.',
      );
      this.hypothesis(
        ctx,
        'server-config',
        'Server Decoder Configuration Differs',
        'authentication',
        'issuer',
        'The server may expect another issuer/audience, algorithm or signing key than the ones simulated here.',
        ['Server configuration is not accessible to TokenScope.'],
        'Compare issuer-uri, jwk-set-uri, audiences and accepted algorithms in the resource server with the token.',
      );
    }
    if (input.httpStatus === '403' && !confirmedAuthz) {
      if (!this.requirementExpression(input)) {
        this.hypothesis(
          ctx,
          'rule-unknown',
          'Endpoint Rule Not Provided',
          'configuration',
          'permission',
          'HTTP 403 is an authorization decision, but no required role/scope/authority was configured for the simulation.',
          ['Required Role / Scope / Authority are empty.'],
          "Fill in the rule protecting the endpoint (e.g. hasRole('ADMIN')) to simulate the decision.",
        );
      } else {
        this.hypothesis(
          ctx,
          'server-mapping',
          'Server Authority Mapping Differs',
          'authorization',
          'mapping',
          'The simulated mapping grants access; the server may use a different JwtAuthenticationConverter, prefix or claim.',
          ['Simulated rule satisfied.'],
          'Log the authorities of the JwtAuthenticationToken on the server and compare them with the simulated ones.',
        );
        this.hypothesis(
          ctx,
          'method-security',
          'Additional Method-Level Rules',
          'authorization',
          'permission',
          'Annotations such as @PreAuthorize/@Secured or custom AuthorizationManagers may impose extra requirements.',
          ['Only the configured rule was simulated.'],
          'Check @PreAuthorize/@PostAuthorize annotations and custom authorization managers for this endpoint.',
        );
      }
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(input.method)) {
        this.hypothesis(
          ctx,
          'csrf',
          'CSRF Protection on State-Changing Request',
          'configuration',
          'final',
          `${input.method} requests can be rejected with 403 by CsrfFilter when CSRF protection is enabled (typical with session/cookie auth).`,
          [`Method: ${input.method}`],
          'For stateless bearer-token APIs, disable CSRF for the API chain or send a valid CSRF token.',
        );
      }
    }
    if (input.httpStatus === 'unknown' && !ctx.causes.length) {
      this.hypothesis(
        ctx,
        'status-unknown',
        'HTTP Status Not Informed',
        'configuration',
        'final',
        'Inform the HTTP status (401 or 403) to focus the diagnosis on authentication or authorization.',
        ['HTTP status: unknown'],
        'Capture the HTTP status and the WWW-Authenticate header returned by the server.',
      );
    }
  }

  private rank(causes: DiagnosisCause[], input: TroubleshooterInput): DiagnosisCause[] {
    const unique = causes.filter(
      (c, i) => causes.findIndex((o) => o.id === c.id && o.reason === c.reason) === i,
    );
    const preferred =
      input.httpStatus === '401'
        ? 'authentication'
        : input.httpStatus === '403'
          ? 'authorization'
          : null;
    return unique.sort((a, b) => {
      const conf = CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
      if (conf) return conf;
      if (preferred) {
        const pa = a.category === preferred ? 0 : 1;
        const pb = b.category === preferred ? 0 : 1;
        if (pa !== pb) return pa - pb;
      }
      return STEP_ORDER.indexOf(a.stepId) - STEP_ORDER.indexOf(b.stepId);
    });
  }

  private outcome(
    causes: DiagnosisCause[],
    steps: DiagnosticStep[],
    input: TroubleshooterInput,
  ): LocalOutcome {
    const top = causes.find((c) => c.confidence === 'confirmed');
    if (top)
      return top.category === 'authorization'
        ? 'authorization-failure'
        : top.category === 'authentication'
          ? 'authentication-failure'
          : 'insufficient-information';
    const likely = causes.find((c) => c.confidence === 'likely');
    if (likely)
      return likely.category === 'authorization'
        ? 'authorization-failure'
        : 'authentication-failure';
    const status = (id: StepId) => steps.find((s) => s.id === id)?.status;
    const permissionUnknown = status('permission') === 'not-applicable';
    const signatureUnknown = status('signature') === 'not-verified';
    if (input.httpStatus === '403' && permissionUnknown) return 'insufficient-information';
    if (input.httpStatus === '401' && signatureUnknown) return 'insufficient-information';
    if (input.httpStatus === 'unknown' && permissionUnknown && signatureUnknown)
      return 'insufficient-information';
    return 'no-issue-detected';
  }

  private headline(
    outcome: LocalOutcome,
    top: DiagnosisCause | null,
    evaluation: RuleEvaluation | null,
    input: TroubleshooterInput,
  ): DiagnosisHeadline {
    switch (outcome) {
      case 'authentication-failure':
        return {
          title: `Most Likely Cause: ${top!.title}`,
          tone: 'danger',
          description: top!.reason,
          simulatedDecision: 'Rejected — Simulated',
        };
      case 'authorization-failure':
        return {
          title: `Most Likely Cause: ${top!.title}`,
          tone: 'danger',
          description: top!.reason,
          simulatedDecision: 'Access Denied — Simulated',
        };
      case 'insufficient-information':
        return {
          title: 'Insufficient Information for a Definitive Diagnosis',
          tone: 'warning',
          description:
            input.httpStatus === '403'
              ? 'Configure the role, scope or authority required by the endpoint to simulate the authorization decision.'
              : 'Authentication checks that could be performed passed, but the signature was not verified. Provide the verification key to rule out signature problems.',
          simulatedDecision: null,
        };
      default:
        return {
          title: 'No Issue Detected in Local Analysis',
          tone: 'success',
          description:
            'Every check that could be performed locally passed. If the server still rejects the request, review the hypotheses below — they depend on server configuration.',
          simulatedDecision: evaluation?.granted ? 'Access Granted — Simulated' : null,
        };
    }
  }

  private statusNote(input: TroubleshooterInput, causes: DiagnosisCause[]): string | null {
    const confirmed = causes.filter((c) => c.confidence === 'confirmed');
    const auth = confirmed.some((c) => c.category === 'authentication');
    const authz = confirmed.some((c) => c.category === 'authorization');
    if (input.httpStatus === '401' && authz && !auth) {
      return 'HTTP 401 means the server did not authenticate the request, yet the local authentication checks did not fail. The authorization problem found would produce 403 — check that this is the token actually sent and that the server decoder accepts it.';
    }
    if (input.httpStatus === '403' && auth) {
      return 'HTTP 403 means the request was authenticated but denied. The authentication problems found locally would normally produce 401 — the server may use a larger clock skew, different validators, or another token than the one analyzed.';
    }
    return null;
  }

  // ---------------------------------------------------------------- report

  buildReport(
    result: DiagnosisResult,
    options: { includeClaims?: boolean; claims?: Record<string, unknown> | null } = {},
  ): string {
    const line = (char: string, n = 64) => char.repeat(n);
    const statusText = {
      '401': '401 Unauthorized',
      '403': '403 Forbidden',
      unknown: 'Unknown / not informed',
    }[result.httpStatus];
    const out: string[] = [
      'TokenScope — Authentication Diagnosis Report',
      line('='),
      `Analysis date     : ${toIso(result.analyzedAt)}`,
      `Request           : ${result.method} ${result.endpoint || '(not informed)'}`,
      `Reported status   : HTTP ${statusText}`,
      `Local outcome     : ${result.headline.title}`,
      ...(result.headline.simulatedDecision
        ? [`Simulated decision: ${result.headline.simulatedDecision}`]
        : []),
      `Checks            : ${result.counts.passed} passed · ${result.counts.failed} failed · ${result.counts.warning} warnings · ${result.counts.notVerified} not verified · ${result.counts.notApplicable} not applicable`,
      '',
      'Verification pipeline',
      line('-'),
    ];
    for (const step of result.steps) {
      out.push(
        `${String(step.index).padStart(2, ' ')}. [${STEP_STATUS_LABEL[step.status].toUpperCase()}] ${step.title} — ${step.summary}`,
      );
      for (const e of step.evidence.slice(0, 6)) out.push(`      · ${e}`);
    }
    if (result.statusNote) out.push('', 'Status consistency', line('-'), result.statusNote);
    if (result.causes.length) {
      out.push('', 'Causes (based on local evidence)', line('-'));
      result.causes.forEach((c, i) => {
        out.push(
          `${i + 1}. ${c.title} [${c.confidence.toUpperCase()} · ${c.category}]`,
          `   Reason: ${c.reason}`,
        );
        for (const e of c.evidence) out.push(`   Evidence: ${e}`);
      });
    }
    if (result.hypotheses.length) {
      out.push('', 'Hypotheses (cannot be verified without server access)', line('-'));
      result.hypotheses.forEach((h, i) => out.push(`${i + 1}. ${h.title} — ${h.reason}`));
    }
    if (result.recommendations.length) {
      out.push('', 'Recommendations', line('-'));
      result.recommendations.forEach((r, i) => out.push(`${i + 1}. ${r}`));
    }
    if (options.includeClaims && options.claims) {
      out.push(
        '',
        'Token claims (included on request — may contain personal data)',
        line('-'),
        JSON.stringify(options.claims, null, 2),
      );
    }
    out.push(
      '',
      line('-'),
      'Notes: The raw JWT, its signature and any keys or secrets are intentionally omitted.',
      'Results are local simulations based on the provided token and rules; they do not',
      'guarantee how the real server behaves.',
    );
    return out.join('\n');
  }

  // ---------------------------------------------------------------- helpers

  private skipped(reason: string): StepDraft {
    return {
      status: 'not-applicable',
      summary: reason,
      analyzed: 'Not executed.',
      data: [],
      evidence: [reason],
      impact: null,
      explanation: 'Later checks depend on a successfully parsed token.',
      recommendations: [],
    };
  }

  private cause(
    ctx: Context,
    id: string,
    title: string,
    category: DiagnosisCause['category'],
    confidence: CauseConfidence,
    stepId: StepId,
    reason: string,
    evidence: string[],
    recommendation: string,
  ): void {
    ctx.causes.push({ id, title, category, confidence, stepId, reason, evidence, recommendation });
  }

  private hypothesis(
    ctx: Context,
    id: string,
    title: string,
    category: DiagnosisCause['category'],
    stepId: StepId,
    reason: string,
    evidence: string[],
    recommendation: string,
  ): void {
    if (ctx.hypotheses.some((h) => h.id === id)) return;
    ctx.hypotheses.push({
      id,
      title,
      category,
      confidence: 'possible',
      stepId,
      reason,
      evidence,
      recommendation,
    });
  }

  private count(steps: DiagnosticStep[]): DiagnosisCounts {
    const c: DiagnosisCounts = {
      passed: 0,
      failed: 0,
      warning: 0,
      notVerified: 0,
      notApplicable: 0,
    };
    for (const s of steps) {
      if (s.status === 'passed') c.passed++;
      else if (s.status === 'failed') c.failed++;
      else if (s.status === 'warning') c.warning++;
      else if (s.status === 'not-verified') c.notVerified++;
      else c.notApplicable++;
    }
    return c;
  }

  private stringHint(actual: string, expected: string): string | null {
    if (actual.replace(/\/+$/, '') === expected.replace(/\/+$/, ''))
      return 'The values differ only by a trailing slash — the comparison is exact.';
    if (actual.toLowerCase() === expected.toLowerCase())
      return 'The values differ only by letter case — the comparison is case-sensitive.';
    if (actual.replace(/^https?:/, '') === expected.replace(/^https?:/, ''))
      return 'The values differ only by the URL scheme (http vs https).';
    try {
      const a = new URL(actual);
      const e = new URL(expected);
      if (a.host !== e.host)
        return `Different hosts: "${a.host}" vs "${e.host}" — possibly another environment.`;
      if (a.pathname !== e.pathname)
        return `Same host, different path (realm/tenant): "${a.pathname}" vs "${e.pathname}".`;
    } catch {
      // not URLs
    }
    return null;
  }

  formatTime(ms: number): string {
    return formatDateTime(ms, 'utc');
  }
}
