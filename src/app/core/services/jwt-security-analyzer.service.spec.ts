import { TestBed } from '@angular/core/testing';
import { NOW, configureClock, fakeToken } from '../../../testing/test-tokens';
import { JwtDecoderService } from './jwt-decoder.service';
import {
  DEFAULT_SECURITY_POLICY,
  JwtSecurityAnalyzerService,
} from './jwt-security-analyzer.service';

describe('JwtSecurityAnalyzerService', () => {
  let analyzer: JwtSecurityAnalyzerService;
  let decoder: JwtDecoderService;

  beforeEach(() => {
    configureClock();
    analyzer = TestBed.inject(JwtSecurityAnalyzerService);
    decoder = TestBed.inject(JwtDecoderService);
  });

  const good = { iss: 'https://issuer', sub: 'u1', aud: 'api', iat: NOW - 60, exp: NOW + 900 };
  const analyze = (
    payload: Record<string, unknown>,
    header?: Record<string, unknown>,
    sig?: string,
  ) =>
    analyzer.analyze(
      decoder.decode(fakeToken(payload, header ?? { alg: 'RS256', typ: 'JWT' }, sig)),
    );
  const ids = (payload: Record<string, unknown>, header?: Record<string, unknown>, sig?: string) =>
    analyze(payload, header, sig).findings.map((f) => f.ruleId);

  it('scores a compliant RS256 token at 100', () => {
    const r = analyze(good);
    expect(r.findings).toEqual([]);
    expect(r.score).toBe(100);
    expect(r.grade).toBe('A');
  });

  it('flags alg none as critical', () => {
    const r = analyze(good, { alg: 'none' }, '');
    expect(r.findings[0].ruleId).toBe('TS-01');
    expect(r.findings[0].severity).toBe('critical');
    expect(r.score).toBe(60);
  });

  it('flags missing exp, iss, aud and sub', () => {
    expect(ids({ iat: NOW })).toEqual(expect.arrayContaining(['TS-02', 'TS-09', 'TS-10', 'TS-11']));
  });

  it('flags expired, not-yet-valid and excessive lifetime', () => {
    expect(ids({ ...good, exp: NOW - 3600 })).toContain('TS-03');
    expect(ids({ ...good, nbf: NOW + 3600, exp: NOW + 4000 })).toContain('TS-04');
    const long = analyze({ ...good, exp: NOW + 3 * 86400 });
    expect(long.findings.find((f) => f.ruleId === 'TS-05')?.severity).toBe('high');
  });

  it('flags inconsistent temporal claims', () => {
    expect(ids({ ...good, iat: NOW + 1000, exp: NOW + 500 })).toEqual(
      expect.arrayContaining(['TS-06', 'TS-08']),
    );
    expect(ids({ ...good, nbf: NOW + 1000, exp: NOW + 500 })).toContain('TS-07');
    expect(ids({ ...good, exp: 'never' })).toContain('TS-12');
  });

  it('flags unsupported algorithms, crit parameters and key references', () => {
    expect(ids(good, { alg: 'XY999' })).toContain('TS-13');
    expect(ids(good, { alg: 'RS256', crit: ['exp-ext'], 'exp-ext': true })).toContain('TS-14');
    expect(ids(good, { alg: 'RS256', jku: 'https://evil.example/jwks' })).toContain('TS-16');
  });

  it('applies the configurable policy', () => {
    const decoded = decoder.decode(fakeToken({ ...good, exp: NOW + 7200 }, { alg: 'HS256' }));
    const strict = analyzer.analyze(decoded, {
      ...DEFAULT_SECURITY_POLICY,
      maxLifetimeMinutes: 30,
      requiredClaims: ['jti'],
      allowedAlgorithms: ['RS256'],
    });
    const titles = strict.findings.map((f) => f.title);
    expect(titles).toEqual(
      expect.arrayContaining([
        'Excessive token lifetime',
        'Required claims missing (policy)',
        'Algorithm not allowed by policy',
      ]),
    );
    const relaxed = analyzer.analyze(decoded, {
      ...DEFAULT_SECURITY_POLICY,
      maxLifetimeMinutes: 240,
    });
    expect(relaxed.findings.map((f) => f.ruleId)).not.toContain('TS-05');
  });

  it('detects sensitive data in the payload', () => {
    expect(ids({ ...good, password: 'hunter2' })).toContain('TS-17');
  });

  it('never goes below zero', () => {
    expect(analyze({ password: 'x' }, { alg: 'none', crit: ['x'], jku: 'u' }, '').score).toBe(0);
  });
});
