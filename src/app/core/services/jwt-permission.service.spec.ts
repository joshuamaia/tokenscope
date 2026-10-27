import { TestBed } from '@angular/core/testing';
import { JwtPermissionService, claimValues } from './jwt-permission.service';

describe('JwtPermissionService', () => {
  let service: JwtPermissionService;

  beforeEach(() => {
    service = TestBed.inject(JwtPermissionService);
  });

  const keycloak = {
    realm_access: { roles: ['offline_access', 'USER'] },
    resource_access: {
      'orders-api': { roles: ['orders-admin'] },
      account: { roles: ['view-profile'] },
    },
    scope: 'openid profile.read',
    authorities: ['READ'],
  };

  it('extracts roles, scopes and authorities including nested and wildcard paths', () => {
    const p = service.extract(keycloak);
    expect(p.roles).toEqual(['offline_access', 'USER', 'orders-admin', 'view-profile']);
    expect(p.scopes).toEqual(['openid', 'profile.read']);
    expect(p.authorities).toEqual(['READ']);
    expect(p.matches.map((m) => m.path)).toContain('resource_access.orders-api.roles');
  });

  it('supports custom sources', () => {
    const sources = service.parseSources('realm_access.roles:role\nscope:scope');
    expect(sources).toEqual([
      { path: 'realm_access.roles', kind: 'role' },
      { path: 'scope', kind: 'scope' },
    ]);
    expect(service.extract(keycloak, sources).authorities).toEqual([]);
  });

  it('splits string claims by delimiter like JwtGrantedAuthoritiesConverter', () => {
    expect(claimValues('a b  c')).toEqual(['a', 'b', 'c']);
    expect(claimValues('a,b', ',')).toEqual(['a', 'b']);
    expect(claimValues(['x', 1, { y: 1 }])).toEqual(['x', '1']);
    expect(claimValues(42)).toEqual([]);
  });

  describe('Spring Security authority mapping', () => {
    it('default converter maps scope → SCOPE_ and ignores roles', () => {
      const r = service.mapAuthorities({ scope: 'read write', roles: ['ADMIN'] }, [
        { claim: 'scope|scp', prefix: 'SCOPE_', delimiter: ' ' },
      ]);
      expect(r.authorities).toEqual(['SCOPE_read', 'SCOPE_write']);
      expect(r.traces[0].claimUsed).toBe('scope');
    });

    it('falls back to scp when scope is absent', () => {
      const r = service.mapAuthorities({ scp: ['a', 'b'] }, [
        { claim: 'scope|scp', prefix: 'SCOPE_', delimiter: ' ' },
      ]);
      expect(r.authorities).toEqual(['SCOPE_a', 'SCOPE_b']);
    });

    it('maps roles: ["ADMIN"] with prefix ROLE_ to ROLE_ADMIN', () => {
      const r = service.mapAuthorities({ roles: ['ADMIN'] }, [
        { claim: 'roles', prefix: 'ROLE_', delimiter: ' ' },
      ]);
      expect(r.authorities).toEqual(['ROLE_ADMIN']);
    });

    it('reports a missing claim', () => {
      const r = service.mapAuthorities({}, [{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }]);
      expect(r.authorities).toEqual([]);
      expect(r.traces[0].note).toContain('not found');
    });

    it('generates the equivalent Java configuration', () => {
      const java = service.javaConfig([{ claim: 'roles', prefix: 'ROLE_', delimiter: ' ' }]);
      expect(java).toContain('setAuthoritiesClaimName("roles")');
      expect(java).toContain('setAuthorityPrefix("ROLE_")');
    });
  });

  describe('expression evaluation', () => {
    const authorities = ['ROLE_USER', 'SCOPE_read'];

    it.each([
      [`hasRole('USER')`, true],
      [`hasRole("ADMIN")`, false],
      [`hasAuthority('ROLE_USER')`, true],
      [`hasAuthority('SCOPE_read')`, true],
      [`hasAnyRole('ADMIN', 'USER')`, true],
      [`hasAnyAuthority('READ', 'WRITE')`, false],
      [`hasAllAuthorities('ROLE_USER', 'SCOPE_read')`, true],
      [`hasRole('USER') and hasAuthority('SCOPE_write')`, false],
      [`hasRole('ADMIN') or hasAuthority('SCOPE_read')`, true],
      [`!hasRole('ADMIN') && (hasRole('USER') || denyAll)`, true],
      [`permitAll`, true],
      [`isAuthenticated()`, true],
    ])('%s → %s', (expression, expected) => {
      const r = service.evaluate(expression, authorities, 'spring');
      expect(r.parsed).toBe(true);
      expect(r.granted).toBe(expected);
    });

    it('lenient mode ignores prefixes and case', () => {
      expect(service.evaluate(`hasRole('admin')`, ['ADMIN'], 'lenient').granted).toBe(true);
      expect(service.evaluate(`hasRole('admin')`, ['ADMIN'], 'spring').granted).toBe(false);
    });

    it('detects ROLE_, SCOPE_ and case near matches', () => {
      const role = service.evaluate(`hasRole('ADMIN')`, ['ADMIN'], 'spring');
      expect(role.checks[0].nearMatches[0].reason).toBe('role-prefix');
      const scope = service.evaluate(`hasAuthority('SCOPE_write')`, ['write'], 'spring');
      expect(scope.checks[0].nearMatches[0].reason).toBe('scope-prefix');
      const caseOnly = service.evaluate(`hasAuthority('admin')`, ['ADMIN'], 'spring');
      expect(caseOnly.checks[0].nearMatches[0].reason).toBe('case');
    });

    it('warns when hasRole receives a ROLE_ prefixed value', () => {
      const r = service.evaluate(`hasRole('ROLE_ADMIN')`, ['ROLE_ADMIN'], 'spring');
      expect(r.granted).toBe(true);
      expect(r.warnings[0]).toContain('IllegalArgumentException');
    });

    it('rejects unsupported functions and malformed input without executing anything', () => {
      expect(service.evaluate(`T(java.lang.Runtime).getRuntime()`, [], 'spring').parsed).toBe(
        false,
      );
      expect(service.evaluate(`constructor('x')`, [], 'spring').parseError).toContain(
        'Unsupported function',
      );
      expect(service.evaluate(`hasRole('A'`, [], 'spring').parsed).toBe(false);
      expect(service.evaluate(`hasRole()`, [], 'spring').parsed).toBe(false);
      expect(
        service.evaluate('('.repeat(100) + `permitAll` + ')'.repeat(100), [], 'spring').parseError,
      ).toContain('nested');
    });

    it('builds expressions from rule types', () => {
      const build = (
        ruleType: Parameters<JwtPermissionService['buildExpression']>[0]['ruleType'],
        roles: string[],
        scopes: string[],
        authorities: string[],
      ) => service.buildExpression({ ruleType, roles, scopes, authorities }, true);
      expect(build('hasRole', ['ADMIN'], [], [])).toBe(`hasRole('ADMIN')`);
      expect(build('hasAnyRole', ['ADMIN', 'MANAGER'], [], [])).toBe(
        `hasAnyRole('ADMIN', 'MANAGER')`,
      );
      expect(build('hasAuthority', [], ['read'], [])).toBe(`hasAuthority('SCOPE_read')`);
      expect(build('hasAnyAuthority', [], [], ['READ', 'WRITE'])).toBe(
        `hasAnyAuthority('READ', 'WRITE')`,
      );
      expect(build('hasAllAuthorities', ['ADMIN'], [], ['READ'])).toBe(
        `hasAllAuthorities('ROLE_ADMIN', 'READ')`,
      );
      expect(build('customOr', ['ADMIN'], ['read'], [])).toBe(
        `hasRole('ADMIN') or hasAuthority('SCOPE_read')`,
      );
      expect(build('customAnd', [], [], [])).toBe('');
    });
  });
});
