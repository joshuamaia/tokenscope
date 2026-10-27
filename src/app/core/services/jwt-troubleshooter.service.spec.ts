import { TestBed } from '@angular/core/testing';
import { NOW, configureClock, fakeToken } from '../../../testing/test-tokens';
import { TroubleshooterInput } from '../models/diagnosis.models';
import { SignatureResult } from '../models/signature.models';
import { JwtGeneratorService } from './jwt-generator.service';
import { JwtSignatureService } from './jwt-signature.service';
import {
  DEFAULT_TROUBLESHOOTER_INPUT,
  JwtTroubleshooterService,
} from './jwt-troubleshooter.service';

const ISSUER = 'https://auth.example.com/realms/app';

function input(overrides: Partial<TroubleshooterInput>): TroubleshooterInput {
  return { ...DEFAULT_TROUBLESHOOTER_INPUT, requiredRoles: '', ...overrides };
}

function basePayload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { iss: ISSUER, sub: 'u1', aud: 'orders-api', iat: NOW - 60, exp: NOW + 600, ...extra };
}

describe('JwtTroubleshooterService', () => {
  let service: JwtTroubleshooterService;

  beforeEach(() => {
    configureClock();
    service = TestBed.inject(JwtTroubleshooterService);
  });

  const step = (result: ReturnType<JwtTroubleshooterService['diagnose']>, id: string) =>
    result.steps.find((s) => s.id === id)!;

  it('always produces the full 10-step pipeline', () => {
    const result = service.diagnose(input({ token: fakeToken(basePayload()) }), null);
    expect(result.steps.map((s) => s.id)).toEqual([
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
    ]);
  });

  it('1. expired token → confirmed authentication cause with evidence', () => {
    const token = fakeToken(basePayload({ iat: NOW - 7200, exp: NOW - 2700 }));
    const result = service.diagnose(
      input({ token, httpStatus: '401', clockSkewSeconds: 60 }),
      null,
    );
    expect(step(result, 'temporal').status).toBe('failed');
    expect(result.mostLikely?.id).toBe('token-expired');
    expect(result.mostLikely?.confidence).toBe('confirmed');
    expect(result.mostLikely?.evidence.some((e) => e.startsWith('Expiration:'))).toBe(true);
    expect(result.outcome).toBe('authentication-failure');
  });

  it('respects clock skew for a token that expired a few seconds ago', () => {
    const token = fakeToken(basePayload({ exp: NOW - 30 }));
    expect(
      step(service.diagnose(input({ token, clockSkewSeconds: 60 }), null), 'temporal').status,
    ).not.toBe('failed');
    expect(
      step(service.diagnose(input({ token, clockSkewSeconds: 0 }), null), 'temporal').status,
    ).toBe('failed');
  });

  it('2. token not yet valid → confirmed cause', () => {
    const token = fakeToken(basePayload({ nbf: NOW + 3600, exp: NOW + 7200 }));
    const result = service.diagnose(input({ token, httpStatus: '401' }), null);
    expect(step(result, 'temporal').status).toBe('failed');
    expect(
      result.causes.some((c) => c.id === 'token-not-yet-valid' && c.confidence === 'confirmed'),
    ).toBe(true);
  });

  it('3. missing role → Access Denied — Simulated', () => {
    const token = fakeToken(basePayload({ roles: ['USER'] }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        ruleType: 'hasRole',
        requiredRoles: 'ADMIN',
        mappingRules: [{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }],
      }),
      null,
    );
    expect(step(result, 'permission').status).toBe('failed');
    expect(result.mostLikely?.id).toBe('missing-role');
    expect(result.mostLikely?.reason).toContain('ROLE_ADMIN');
    expect(result.headline.simulatedDecision).toBe('Access Denied — Simulated');
    expect(result.outcome).toBe('authorization-failure');
  });

  it('4. missing scope → insufficient scope', () => {
    const token = fakeToken(basePayload({ scope: 'openid profile.read' }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        ruleType: 'hasAuthority',
        requiredScopes: 'profile.write',
      }),
      null,
    );
    expect(result.mostLikely?.id).toBe('missing-scope');
    expect(result.evaluation?.expression).toBe("hasAuthority('SCOPE_profile.write')");
  });

  it('5. issuer mismatch → confirmed, with trailing slash hint', () => {
    const token = fakeToken(basePayload({ iss: ISSUER + '/' }));
    const result = service.diagnose(
      input({ token, httpStatus: '401', expectedIssuer: ISSUER }),
      null,
    );
    expect(step(result, 'issuer').status).toBe('failed');
    expect(result.mostLikely?.id).toBe('issuer-mismatch');
    expect(result.mostLikely?.evidence.join(' ')).toContain('trailing slash');
  });

  it('6. audience mismatch → confirmed', () => {
    const token = fakeToken(basePayload({ aud: ['billing-api'] }));
    const result = service.diagnose(
      input({ token, httpStatus: '401', expectedAudience: 'orders-api' }),
      null,
    );
    expect(step(result, 'audience').status).toBe('failed');
    expect(result.causes[0].id).toBe('audience-mismatch');
  });

  it('issuer and audience are not applicable when not configured', () => {
    const result = service.diagnose(input({ token: fakeToken(basePayload()) }), null);
    expect(step(result, 'issuer').status).toBe('not-applicable');
    expect(step(result, 'audience').status).toBe('not-applicable');
  });

  it('7. invalid signature (real verification) → confirmed authentication failure', async () => {
    const generator = TestBed.inject(JwtGeneratorService);
    const signature = TestBed.inject(JwtSignatureService);
    const secret = 'a-test-secret-with-at-least-256-bits-0123456789';
    const valid = await generator.sign(basePayload({ roles: ['USER'] }), {
      alg: 'HS256',
      secret,
      encoding: 'utf8',
    });
    const [h, , s] = valid.split('.');
    const tampered = `${h}.${fakeToken(basePayload({ roles: ['ADMIN'] })).split('.')[1]}.${s}`;
    const verification = await signature.verify(tampered, {
      type: 'secret',
      value: secret,
      encoding: 'utf8',
    });
    const result = service.diagnose(
      input({ token: tampered, httpStatus: '401', signatureMode: 'verify-now' }),
      verification,
    );
    expect(step(result, 'signature').status).toBe('failed');
    expect(result.mostLikely?.id).toBe('invalid-signature');
    expect(result.mostLikely?.confidence).toBe('confirmed');
  });

  it('8. signature not verified → Not Verified step and a hypothesis, never Passed', () => {
    const result = service.diagnose(
      input({ token: fakeToken(basePayload()), httpStatus: '401' }),
      null,
    );
    expect(step(result, 'signature').status).toBe('not-verified');
    expect(
      result.hypotheses.some((h) => h.id === 'signature-unverified' && h.confidence === 'possible'),
    ).toBe(true);
    expect(result.causes.every((c) => c.confidence !== 'confirmed')).toBe(true);
  });

  it('uses a Signature Verifier result only when it exists', () => {
    const verified: SignatureResult = {
      status: 'verified',
      alg: 'HS256',
      title: 'Signature Verified',
      message: 'ok',
      details: [],
      warnings: [],
      checkedAt: 0,
    };
    const result = service.diagnose(
      input({ token: fakeToken(basePayload()), signatureMode: 'use-verifier' }),
      verified,
    );
    expect(step(result, 'signature').status).toBe('passed');
  });

  it('9. ROLE_ prefix mismatch → detected as prefix problem', () => {
    const token = fakeToken(basePayload({ authorities: ['ADMIN'] }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        ruleType: 'hasRole',
        requiredRoles: 'ADMIN',
        mappingRules: [{ claim: 'authorities', prefix: '', delimiter: ' ' }],
      }),
      null,
    );
    expect(result.mostLikely?.id).toBe('role-prefix-mismatch');
    expect(result.mostLikely?.confidence).toBe('confirmed');
  });

  it('10. SCOPE_ prefix mismatch → detected when the rule omits SCOPE_', () => {
    const token = fakeToken(basePayload({ scope: 'orders.read' }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        ruleType: 'hasAuthority',
        requiredAuthorities: 'orders.read',
      }),
      null,
    );
    expect(result.mostLikely?.id).toBe('scope-prefix-mismatch');
  });

  it('detects a permission claim that the converter does not map (Spring default mapping)', () => {
    const token = fakeToken(basePayload({ roles: ['ADMIN'], scope: 'openid' }));
    const result = service.diagnose(
      input({ token, httpStatus: '403', ruleType: 'hasRole', requiredRoles: 'ADMIN' }),
      null,
    );
    expect(result.mostLikely?.id).toBe('claim-not-mapped');
    expect(result.suggestedMapping?.at(-1)).toEqual({
      claim: 'roles',
      prefix: 'ROLE_',
      delimiter: ' ',
    });

    const fixed = service.diagnose(
      input({
        token,
        httpStatus: '403',
        ruleType: 'hasRole',
        requiredRoles: 'ADMIN',
        mappingRules: result.suggestedMapping!,
      }),
      null,
    );
    expect(fixed.evaluation?.granted).toBe(true);
    expect(fixed.headline.simulatedDecision).toBe('Access Granted — Simulated');
  });

  it('11. insufficient configuration → Insufficient Information, no invented evidence', () => {
    const result = service.diagnose(
      input({ token: fakeToken(basePayload({ roles: ['USER'] })), httpStatus: '403' }),
      null,
    );
    expect(step(result, 'permission').status).toBe('not-applicable');
    expect(result.outcome).toBe('insufficient-information');
    expect(result.headline.title).toBe('Insufficient Information for a Definitive Diagnosis');
    expect(result.causes.filter((c) => c.confidence === 'confirmed')).toHaveLength(0);
  });

  it('12. temporally valid token without sufficient permission → authorization failure only', () => {
    const token = fakeToken(basePayload({ roles: ['USER'] }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        ruleType: 'hasAnyRole',
        requiredRoles: 'ADMIN, MANAGER',
        mappingRules: [{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }],
      }),
      null,
    );
    expect(step(result, 'temporal').status).toBe('passed');
    expect(step(result, 'permission').status).toBe('failed');
    expect(result.causes.every((c) => c.category === 'authorization')).toBe(true);
  });

  it('distinguishes confirmed causes from hypotheses (CSRF on POST)', () => {
    const token = fakeToken(basePayload({ roles: ['ADMIN'] }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        method: 'POST',
        ruleType: 'hasRole',
        requiredRoles: 'ADMIN',
        mappingRules: [{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }],
      }),
      null,
    );
    expect(result.outcome).toBe('no-issue-detected');
    expect(result.causes).toHaveLength(0);
    expect(result.hypotheses.map((h) => h.id)).toContain('csrf');
    expect(result.hypotheses.every((h) => h.confidence === 'possible')).toBe(true);
  });

  it('reports a missing token and malformed tokens as structural failures', () => {
    const empty = service.diagnose(input({ token: '', httpStatus: '401' }), null);
    expect(empty.mostLikely?.id).toBe('token-missing');
    expect(empty.steps.slice(1, 9).every((s) => s.status === 'not-applicable')).toBe(true);

    const malformed = service.diagnose(input({ token: 'abc.def', httpStatus: '401' }), null);
    expect(malformed.mostLikely?.id).toBe('malformed-token');
  });

  it('flags alg none as a confirmed failure', () => {
    const token = fakeToken(basePayload(), { alg: 'none' }, '');
    const result = service.diagnose(input({ token, httpStatus: '401' }), null);
    expect(step(result, 'signature').status).toBe('failed');
    expect(result.mostLikely?.id).toBe('alg-none');
  });

  it('adds a status consistency note when 401 is reported but only authorization fails', () => {
    const token = fakeToken(basePayload({ roles: ['USER'] }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '401',
        requiredRoles: 'ADMIN',
        mappingRules: [{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }],
      }),
      null,
    );
    expect(result.statusNote).toContain('HTTP 401');
  });

  it('builds a report without the raw token or signature', () => {
    const token = fakeToken(basePayload({ roles: ['USER'] }));
    const result = service.diagnose(
      input({
        token,
        httpStatus: '403',
        requiredRoles: 'ADMIN',
        mappingRules: [{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }],
      }),
      null,
    );
    const report = service.buildReport(result);
    expect(report).toContain('GET /api/admin/users');
    expect(report).toContain('Permission Evaluation');
    expect(report).not.toContain(token);
    expect(report).not.toContain(token.split('.')[2]);
    expect(report).not.toContain('"sub"');
    expect(service.buildReport(result, { includeClaims: true, claims: { sub: 'u1' } })).toContain(
      '"sub"',
    );
  });
});
