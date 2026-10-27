import { TestBed } from '@angular/core/testing';
import { NOW, configureClock, fakeToken } from '../../../testing/test-tokens';
import { deepDiff } from '../utils/deep-diff';
import { JwtCompareService } from './jwt-compare.service';
import { JwtDecoderService } from './jwt-decoder.service';

describe('deepDiff', () => {
  it('classifies added, removed, modified and unchanged entries', () => {
    const diff = deepDiff(
      { a: 1, b: { c: 1, d: [1, 2] }, e: 'x' },
      { a: 1, b: { c: 2, d: [2, 1] }, f: true },
    );
    const byPath = Object.fromEntries(diff.map((d) => [d.path, d.kind]));
    expect(byPath).toEqual({
      a: 'unchanged',
      'b.c': 'modified',
      'b.d': 'unchanged',
      e: 'removed',
      f: 'added',
    });
  });

  it('compares arrays of objects by index', () => {
    const diff = deepDiff([{ id: 1 }], [{ id: 2 }, { id: 3 }]);
    expect(diff.map((d) => `${d.path}:${d.kind}`)).toEqual(['[0].id:modified', '[1]:added']);
  });
});

describe('JwtCompareService', () => {
  it('produces a smart summary of permissions, expiration and issuer', () => {
    configureClock();
    const decoder = TestBed.inject(JwtDecoderService);
    const service = TestBed.inject(JwtCompareService);
    const a = decoder.decode(
      fakeToken({ iss: 'https://a', sub: 'u1', roles: ['USER'], scope: 'read', exp: NOW + 600 }),
    );
    const b = decoder.decode(
      fakeToken({
        iss: 'https://b',
        sub: 'u1',
        roles: ['USER', 'ADMIN'],
        scope: 'read write',
        exp: NOW + 3600,
      }),
    );
    const result = service.compare(a, b);
    expect(result.summary).toContain('Token B contains ROLE_ADMIN, which is missing from Token A.');
    expect(result.summary).toContain(
      'Token B contains SCOPE_write, which is missing from Token A.',
    );
    expect(result.summary.some((s) => s.startsWith('Token A expires earlier than Token B'))).toBe(
      true,
    );
    expect(result.summary).toContain('Both tokens use different issuers.');
    expect(result.summary).toContain('Both tokens belong to the same subject.');
    expect(result.permissions[0].onlyB).toEqual(['ROLE_ADMIN']);
    expect(result.stats.modified).toBe(4);
    expect(service.report(result)).toContain('[MODIFIED] iss');
  });
});
