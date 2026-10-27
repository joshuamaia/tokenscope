import { TestBed } from '@angular/core/testing';
import { NOW, configureClock, fakeToken } from '../../../testing/test-tokens';
import { MAX_TOKEN_LENGTH } from '../models/jwt.models';
import { stringToBase64Url } from '../utils/base64url';
import { JwtClaimsService } from './jwt-claims.service';
import { JwtDecoderService } from './jwt-decoder.service';

describe('JwtDecoderService', () => {
  let decoder: JwtDecoderService;

  beforeEach(() => {
    configureClock();
    decoder = TestBed.inject(JwtDecoderService);
  });

  const errorCodes = (token: string) =>
    decoder
      .decode(token)
      .issues.filter((i) => i.severity === 'error')
      .map((i) => i.code);

  it('decodes a well-formed JWS', () => {
    const result = decoder.decode(fakeToken({ sub: 'u1', exp: NOW + 60 }));
    expect(result.kind).toBe('jws');
    expect(result.valid).toBe(true);
    expect(result.alg).toBe('HS256');
    expect(result.payload).toEqual({ sub: 'u1', exp: NOW + 60 });
    expect(result.signatureLength).toBe(9);
  });

  it('rejects empty input', () => {
    expect(errorCodes('')).toEqual(['empty']);
    expect(decoder.decode('   ').kind).toBe('empty');
  });

  it('rejects tokens with the wrong number of segments', () => {
    expect(errorCodes('abc.def')).toEqual(['segments']);
    expect(errorCodes('a.b.c.d')).toEqual(['segments']);
  });

  it('identifies JWE tokens instead of misreading them as JWS', () => {
    const header = stringToBase64Url(JSON.stringify({ alg: 'RSA-OAEP', enc: 'A256GCM' }));
    const result = decoder.decode(`${header}.key.iv.cipher.tag`);
    expect(result.kind).toBe('jwe');
    expect(result.decoded).toBe(false);
    expect(result.payload).toBeNull();
    expect(result.alg).toBe('RSA-OAEP');
  });

  it('detects invalid Base64URL (standard Base64 characters)', () => {
    const token = fakeToken({ a: 1 });
    const [h, , s] = token.split('.');
    expect(errorCodes(`${h}.ab+/cd==.${s}`)).toContain('payload-base64');
  });

  it('detects invalid JSON and non-object JSON', () => {
    const h = stringToBase64Url('{"alg":"HS256"}');
    expect(errorCodes(`${h}.${stringToBase64Url('{not json')}.c2ln`)).toContain('payload-json');
    expect(errorCodes(`${h}.${stringToBase64Url('[1,2]')}.c2ln`)).toContain('payload-not-object');
  });

  it('detects claims with incorrect types', () => {
    const codes = errorCodes(fakeToken({ exp: '2026-01-01', iss: 42, aud: [1, 2] }));
    expect(codes).toEqual(
      expect.arrayContaining(['claim-type-exp', 'claim-type-iss', 'claim-type-aud']),
    );
  });

  it('warns about NumericDate in milliseconds', () => {
    const issues = decoder.decode(fakeToken({ exp: NOW * 1000 })).issues;
    expect(issues.some((i) => i.code === 'claim-ms-exp' && i.severity === 'warning')).toBe(true);
  });

  it('flags a missing alg and inconsistent alg none', () => {
    expect(errorCodes(fakeToken({}, { typ: 'JWT' }))).toContain('alg-missing');
    expect(errorCodes(fakeToken({}, { alg: 'none' }))).toContain('none-with-signature');
    expect(errorCodes(fakeToken({}, { alg: 'RS256' }, ''))).toContain('signature-missing');
  });

  it('normalizes Bearer prefix, quotes and whitespace', () => {
    const token = fakeToken({ sub: 'x' });
    const result = decoder.decode(`Bearer "${token.slice(0, 10)}\n${token.slice(10)}"`);
    expect(result.valid).toBe(true);
    expect(result.token).toBe(token);
    expect(result.issues.map((i) => i.code)).toEqual(
      expect.arrayContaining(['bearer-prefix', 'quoted', 'whitespace']),
    );
  });

  it('refuses inputs above the size limit without processing them', () => {
    const result = decoder.decode('a'.repeat(MAX_TOKEN_LENGTH + 1));
    expect(result.issues[0].code).toBe('too-large');
    expect(result.segments).toBeNull();
  });

  it('never evaluates claim content', () => {
    const result = decoder.decode(
      fakeToken({ name: '<img src=x onerror=alert(1)>', __proto__: { polluted: true } }),
    );
    expect(result.payload?.['name']).toBe('<img src=x onerror=alert(1)>');
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});

describe('JwtClaimsService', () => {
  it('describes registered, permission and custom claims with timestamps', () => {
    configureClock();
    const claims = TestBed.inject(JwtClaimsService);
    const views = claims.describe({ exp: NOW, roles: ['ADMIN'], foo: 'bar' });
    expect(views.find((v) => v.key === 'exp')?.timestamp).toBe(NOW * 1000);
    expect(views.find((v) => v.key === 'roles')?.doc?.category).toBe('permission');
    expect(views.find((v) => v.key === 'foo')?.doc).toBeNull();
    expect(claims.audiences({ aud: 'a' })).toEqual(['a']);
    expect(claims.audiences({ aud: ['a', 'b'] })).toEqual(['a', 'b']);
  });
});
