import { Injectable } from '@angular/core';
import { JwtPayload } from '../models/jwt.models';
import {
  AuthorityMappingResult,
  AuthorityMappingRule,
  AuthorityMappingTrace,
  ExpressionCheck,
  ExpressionNode,
  ExtractedPermissions,
  MatchMode,
  NearMatch,
  PermissionClaimMatch,
  PermissionSource,
  RequirementInput,
  RuleEvaluation,
} from '../models/permission.models';
import { resolvePath } from '../utils/json-path';

export const DEFAULT_PERMISSION_SOURCES: PermissionSource[] = [
  { path: 'roles', kind: 'role' },
  { path: 'role', kind: 'role' },
  { path: 'realm_access.roles', kind: 'role' },
  { path: 'resource_access.*.roles', kind: 'role' },
  { path: 'authorities', kind: 'authority' },
  { path: 'permissions', kind: 'authority' },
  { path: 'groups', kind: 'authority' },
  { path: 'scope', kind: 'scope' },
  { path: 'scp', kind: 'scope' },
];

const MAX_EXPRESSION_LENGTH = 2000;
const MAX_DEPTH = 32;

const SUPPORTED_FUNCTIONS = [
  'hasRole',
  'hasAnyRole',
  'hasAllRoles',
  'hasAuthority',
  'hasAnyAuthority',
  'hasAllAuthorities',
  'permitAll',
  'denyAll',
  'isAuthenticated',
  'isFullyAuthenticated',
  'isAnonymous',
];

export function stripPrefix(value: string): string {
  return value.replace(/^(ROLE_|SCOPE_)/i, '');
}

function normalize(value: string): string {
  return stripPrefix(value).toLowerCase();
}

/** Converts a claim value into string values the way JwtGrantedAuthoritiesConverter does. */
export function claimValues(value: unknown, delimiter = ' '): string[] {
  if (typeof value === 'string') {
    const parts = delimiter ? value.split(delimiter) : [value];
    return parts.map((v) => v.trim()).filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value
      .flatMap((v) => (typeof v === 'string' || typeof v === 'number' ? [String(v).trim()] : []))
      .filter(Boolean);
  }
  return [];
}

/**
 * Permission interpretation and Spring Security rule simulation.
 * Results are simulations of the configured rules — not the server's actual decision.
 */
@Injectable({ providedIn: 'root' })
export class JwtPermissionService {
  extract(
    payload: JwtPayload | null,
    sources: PermissionSource[] = DEFAULT_PERMISSION_SOURCES,
  ): ExtractedPermissions {
    const result: ExtractedPermissions = { roles: [], scopes: [], authorities: [], matches: [] };
    if (!payload) return result;
    for (const source of sources) {
      for (const match of resolvePath(payload, source.path)) {
        const values = claimValues(match.value);
        if (values.length === 0) continue;
        const entry: PermissionClaimMatch = { path: match.path, kind: source.kind, values };
        result.matches.push(entry);
        const bucket =
          source.kind === 'role'
            ? result.roles
            : source.kind === 'scope'
              ? result.scopes
              : result.authorities;
        for (const v of values) if (!bucket.includes(v)) bucket.push(v);
      }
    }
    return result;
  }

  /** Parses user-provided source definitions like "roles:role, realm_access.roles:role, scope:scope". */
  parseSources(text: string): PermissionSource[] {
    return text
      .split(/[\n,]+/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [path, kind] = line.split(':').map((p) => p.trim());
        const k = kind === 'scope' || kind === 'authority' || kind === 'role' ? kind : 'authority';
        return { path, kind: k } as PermissionSource;
      })
      .filter((s) => s.path.length > 0);
  }

  /** Simulates JwtGrantedAuthoritiesConverter(s) combined into one authority list. */
  mapAuthorities(
    payload: JwtPayload | null,
    rules: AuthorityMappingRule[],
  ): AuthorityMappingResult {
    const traces: AuthorityMappingTrace[] = [];
    const authorities: string[] = [];
    for (const rule of rules) {
      const alternatives = rule.claim
        .split('|')
        .map((c) => c.trim())
        .filter(Boolean);
      let claimUsed: string | null = null;
      let rawValues: string[] = [];
      let note = '';
      for (const alternative of alternatives) {
        const matches = payload ? resolvePath(payload, alternative) : [];
        if (matches.length === 0) continue;
        claimUsed = alternative;
        rawValues = matches.flatMap((m) => claimValues(m.value, rule.delimiter));
        const unsupported = matches.filter(
          (m) => typeof m.value !== 'string' && !Array.isArray(m.value),
        );
        if (unsupported.length)
          note = `Claim "${alternative}" is not a string or collection; Spring ignores it.`;
        break;
      }
      if (!claimUsed) {
        note = `Claim ${alternatives.map((a) => `"${a}"`).join(' / ')} not found in the token — this converter produces no authorities.`;
      } else if (!note) {
        note = rawValues.length
          ? `Read "${claimUsed}" and prefixed ${rawValues.length} value(s) with "${rule.prefix}".`
          : `Claim "${claimUsed}" is present but empty.`;
      }
      const mapped = rawValues.map((v) => `${rule.prefix}${v}`);
      for (const m of mapped) if (!authorities.includes(m)) authorities.push(m);
      traces.push({ rule, claimUsed, rawValues, mapped, note });
    }
    return { authorities, traces };
  }

  /** Builds a Spring Security expression from the troubleshooter fields. */
  buildExpression(req: RequirementInput, springMode: boolean): string {
    const q = (v: string) => `'${v.replace(/'/g, '')}'`;
    const scopes = req.scopes.map((s) =>
      springMode && !s.startsWith('SCOPE_') ? `SCOPE_${s}` : s,
    );
    const others = [...scopes, ...req.authorities];
    const roleAuthorities = req.roles.map((r) => (r.startsWith('ROLE_') ? r : `ROLE_${r}`));
    const all = [...roleAuthorities, ...others];
    const join = (parts: string[], op: 'and' | 'or') => parts.filter(Boolean).join(` ${op} `);

    switch (req.ruleType) {
      case 'hasRole':
        return join(
          [
            ...req.roles.map((r) => `hasRole(${q(r)})`),
            ...others.map((a) => `hasAuthority(${q(a)})`),
          ],
          'and',
        );
      case 'hasAnyRole':
        return join(
          [
            req.roles.length ? `hasAnyRole(${req.roles.map(q).join(', ')})` : '',
            others.length ? `hasAnyAuthority(${others.map(q).join(', ')})` : '',
          ],
          'or',
        );
      case 'hasAuthority':
        return join(
          all.map((a) => `hasAuthority(${q(a)})`),
          'and',
        );
      case 'hasAnyAuthority':
        return all.length ? `hasAnyAuthority(${all.map(q).join(', ')})` : '';
      case 'hasAllAuthorities':
        return all.length ? `hasAllAuthorities(${all.map(q).join(', ')})` : '';
      case 'customAnd':
        return join(
          [
            ...req.roles.map((r) => `hasRole(${q(r)})`),
            ...others.map((a) => `hasAuthority(${q(a)})`),
          ],
          'and',
        );
      case 'customOr':
        return join(
          [
            ...req.roles.map((r) => `hasRole(${q(r)})`),
            ...others.map((a) => `hasAuthority(${q(a)})`),
          ],
          'or',
        );
    }
  }

  parse(expression: string): { ast: ExpressionNode | null; error?: string } {
    if (expression.length > MAX_EXPRESSION_LENGTH)
      return {
        ast: null,
        error: `Expression is too long (max ${MAX_EXPRESSION_LENGTH} characters).`,
      };
    try {
      const parser = new ExpressionParser(expression);
      return { ast: parser.parse() };
    } catch (e) {
      return { ast: null, error: (e as Error).message };
    }
  }

  evaluate(expression: string, authorities: string[], mode: MatchMode = 'spring'): RuleEvaluation {
    const trimmed = expression.trim();
    const base: RuleEvaluation = {
      expression: trimmed,
      parsed: false,
      granted: false,
      checks: [],
      warnings: [],
    };
    if (!trimmed) return { ...base, parseError: 'No rule configured.' };
    const { ast, error } = this.parse(trimmed);
    if (!ast) return { ...base, parseError: error };
    const checks: ExpressionCheck[] = [];
    const warnings: string[] = [];
    const granted = this.evalNode(ast, authorities, mode, checks, warnings);
    return { expression: trimmed, parsed: true, granted, checks, warnings: [...new Set(warnings)] };
  }

  private evalNode(
    node: ExpressionNode,
    authorities: string[],
    mode: MatchMode,
    checks: ExpressionCheck[],
    warnings: string[],
  ): boolean {
    switch (node.type) {
      case 'and': {
        // Evaluate both sides so the trace shows every missing requirement.
        const left = this.evalNode(node.left, authorities, mode, checks, warnings);
        const right = this.evalNode(node.right, authorities, mode, checks, warnings);
        return left && right;
      }
      case 'or': {
        const left = this.evalNode(node.left, authorities, mode, checks, warnings);
        const right = this.evalNode(node.right, authorities, mode, checks, warnings);
        return left || right;
      }
      case 'not':
        return !this.evalNode(node.expr, authorities, mode, checks, warnings);
      case 'call':
        return this.evalCall(node.fn, node.args, authorities, mode, checks, warnings);
    }
  }

  private evalCall(
    fn: string,
    args: string[],
    authorities: string[],
    mode: MatchMode,
    checks: ExpressionCheck[],
    warnings: string[],
  ): boolean {
    const expression = `${fn}(${args.map((a) => `'${a}'`).join(', ')})`;
    const record = (required: string[], any: boolean): boolean => {
      const matched = required.filter((r) => this.has(authorities, r, mode));
      const missing = required.filter((r) => !matched.includes(r));
      const result = any ? matched.length > 0 : missing.length === 0 && required.length > 0;
      const nearMatches = result ? [] : missing.flatMap((r) => this.nearMatches(r, authorities));
      checks.push({
        expression,
        fn,
        required,
        matched,
        missing: any && result ? [] : missing,
        result,
        nearMatches,
      });
      return result;
    };
    const roles = (list: string[]) =>
      list.map((r) => {
        if (r.startsWith('ROLE_')) {
          warnings.push(
            `${fn}('${r}'): role names should not start with "ROLE_". Spring Security 6 authorizeHttpRequests throws IllegalArgumentException; @PreAuthorize uses it unchanged. Use hasRole('${r.slice(5)}') or hasAuthority('${r}').`,
          );
          return r;
        }
        return `ROLE_${r}`;
      });

    switch (fn) {
      case 'hasRole':
        return record(roles(args.slice(0, 1)), false);
      case 'hasAnyRole':
        return record(roles(args), true);
      case 'hasAllRoles':
        return record(roles(args), false);
      case 'hasAuthority':
        return record(args.slice(0, 1), false);
      case 'hasAnyAuthority':
        return record(args, true);
      case 'hasAllAuthorities':
        return record(args, false);
      case 'permitAll':
        checks.push({
          expression: 'permitAll',
          fn,
          required: [],
          matched: [],
          missing: [],
          result: true,
          nearMatches: [],
        });
        return true;
      case 'denyAll':
        checks.push({
          expression: 'denyAll',
          fn,
          required: [],
          matched: [],
          missing: [],
          result: false,
          nearMatches: [],
        });
        return false;
      case 'isAuthenticated':
      case 'isFullyAuthenticated':
        warnings.push(`${fn}() is assumed true for a token that passes authentication checks.`);
        checks.push({
          expression: `${fn}()`,
          fn,
          required: [],
          matched: [],
          missing: [],
          result: true,
          nearMatches: [],
        });
        return true;
      case 'isAnonymous':
        checks.push({
          expression: 'isAnonymous()',
          fn,
          required: [],
          matched: [],
          missing: [],
          result: false,
          nearMatches: [],
        });
        return false;
      default:
        return false;
    }
  }

  private has(authorities: string[], required: string, mode: MatchMode): boolean {
    if (mode === 'spring') return authorities.includes(required);
    const n = normalize(required);
    return authorities.some((a) => normalize(a) === n);
  }

  nearMatches(required: string, authorities: string[]): NearMatch[] {
    const n = normalize(required);
    return authorities
      .filter((a) => a !== required && normalize(a) === n)
      .map((found) => {
        let reason: NearMatch['reason'] = 'other-prefix';
        if (required.startsWith('ROLE_') && !found.startsWith('ROLE_')) reason = 'role-prefix';
        else if (required.startsWith('SCOPE_') && !found.startsWith('SCOPE_'))
          reason = 'scope-prefix';
        else if (found.toLowerCase() === required.toLowerCase()) reason = 'case';
        else if (found.startsWith('ROLE_') && !required.startsWith('ROLE_')) reason = 'role-prefix';
        else if (found.startsWith('SCOPE_') && !required.startsWith('SCOPE_'))
          reason = 'scope-prefix';
        return { required, found, reason };
      });
  }

  /** Java configuration equivalent to the simulated mapping rules. */
  javaConfig(rules: AuthorityMappingRule[]): string {
    if (rules.length === 0) {
      return '// No authority mapping configured: the JwtAuthenticationToken will have no authorities.';
    }
    const isDefault =
      rules.length === 1 &&
      rules[0].claim === 'scope|scp' &&
      rules[0].prefix === 'SCOPE_' &&
      rules[0].delimiter === ' ';
    if (isDefault) {
      return [
        '// Spring Security default: JwtGrantedAuthoritiesConverter reads "scope" (or "scp")',
        '// and prefixes each value with "SCOPE_". No extra configuration is required.',
        '@Bean',
        'SecurityFilterChain api(HttpSecurity http) throws Exception {',
        '    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));',
        '    return http.build();',
        '}',
      ].join('\n');
    }
    const lines: string[] = ['@Bean', 'JwtAuthenticationConverter jwtAuthenticationConverter() {'];
    const names: string[] = [];
    rules.forEach((rule, i) => {
      const name = rules.length === 1 ? 'authorities' : `converter${i + 1}`;
      names.push(name);
      const claim = rule.claim.split('|')[0];
      if (claim.includes('.')) {
        lines.push(
          `    // "${claim}" is nested: JwtGrantedAuthoritiesConverter only reads top-level claims.`,
        );
        lines.push(`    Converter<Jwt, Collection<GrantedAuthority>> ${name} = jwt -> {`);
        const [root, ...rest] = claim.split('.');
        lines.push(`        Map<String, Object> ${root} = jwt.getClaimAsMap("${root}");`);
        lines.push(
          `        Collection<String> values = /* navigate ${rest.join(' → ')} */ List.of();`,
        );
        lines.push(
          `        return values.stream().map(v -> new SimpleGrantedAuthority("${rule.prefix}" + v))`,
        );
        lines.push('                .collect(Collectors.toList());');
        lines.push('    };');
      } else {
        lines.push(
          `    JwtGrantedAuthoritiesConverter ${name} = new JwtGrantedAuthoritiesConverter();`,
        );
        if (rule.claim !== 'scope|scp')
          lines.push(`    ${name}.setAuthoritiesClaimName("${claim}");`);
        if (rule.prefix !== 'SCOPE_')
          lines.push(`    ${name}.setAuthorityPrefix("${rule.prefix}");`);
        if (rule.delimiter !== ' ')
          lines.push(
            `    ${name}.setAuthoritiesClaimDelimiter("${rule.delimiter.replace(/\\/g, '\\\\')}");`,
          );
      }
    });
    lines.push('', '    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();');
    if (names.length === 1) {
      lines.push(`    converter.setJwtGrantedAuthoritiesConverter(${names[0]});`);
    } else {
      lines.push(
        '    converter.setJwtGrantedAuthoritiesConverter(jwt -> Stream.of(' +
          names.join(', ') +
          ')',
      );
      lines.push('            .flatMap(c -> c.convert(jwt).stream())');
      lines.push('            .collect(Collectors.toSet()));');
    }
    lines.push('    return converter;', '}');
    return lines.join('\n');
  }
}

type Token = {
  type: 'ident' | 'string' | 'lparen' | 'rparen' | 'comma' | 'and' | 'or' | 'not';
  value: string;
};

/** Recursive-descent parser for a safe subset of Spring Security SpEL. Never evaluates code. */
class ExpressionParser {
  private readonly tokens: Token[];
  private pos = 0;
  private depth = 0;

  constructor(source: string) {
    this.tokens = this.tokenize(source);
  }

  parse(): ExpressionNode {
    if (this.tokens.length === 0) throw new Error('Expression is empty.');
    const node = this.parseOr();
    if (this.pos < this.tokens.length)
      throw new Error(`Unexpected "${this.tokens[this.pos].value}" at token ${this.pos + 1}.`);
    return node;
  }

  private tokenize(source: string): Token[] {
    const tokens: Token[] = [];
    let i = 0;
    while (i < source.length) {
      const c = source[i];
      if (/\s/.test(c)) {
        i++;
      } else if (c === '(') {
        tokens.push({ type: 'lparen', value: c });
        i++;
      } else if (c === ')') {
        tokens.push({ type: 'rparen', value: c });
        i++;
      } else if (c === ',') {
        tokens.push({ type: 'comma', value: c });
        i++;
      } else if (c === '!') {
        tokens.push({ type: 'not', value: c });
        i++;
      } else if (source.startsWith('&&', i)) {
        tokens.push({ type: 'and', value: '&&' });
        i += 2;
      } else if (source.startsWith('||', i)) {
        tokens.push({ type: 'or', value: '||' });
        i += 2;
      } else if (c === "'" || c === '"') {
        const end = source.indexOf(c, i + 1);
        if (end === -1) throw new Error('Unterminated string literal.');
        tokens.push({ type: 'string', value: source.slice(i + 1, end) });
        i = end + 1;
      } else if (/[A-Za-z_]/.test(c)) {
        let j = i;
        while (j < source.length && /[A-Za-z0-9_]/.test(source[j])) j++;
        const word = source.slice(i, j);
        const lower = word.toLowerCase();
        if (lower === 'and') tokens.push({ type: 'and', value: word });
        else if (lower === 'or') tokens.push({ type: 'or', value: word });
        else if (lower === 'not') tokens.push({ type: 'not', value: word });
        else tokens.push({ type: 'ident', value: word });
        i = j;
      } else {
        throw new Error(`Unexpected character "${c}" at position ${i + 1}.`);
      }
    }
    return tokens;
  }

  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }

  private expect(type: Token['type']): Token {
    const token = this.tokens[this.pos];
    if (!token || token.type !== type)
      throw new Error(
        `Expected ${type === 'rparen' ? '")"' : type === 'lparen' ? '"("' : type} ${token ? `but found "${token.value}"` : 'at end of expression'}.`,
      );
    this.pos++;
    return token;
  }

  private enter(): void {
    if (++this.depth > MAX_DEPTH) throw new Error('Expression is nested too deeply.');
  }

  private parseOr(): ExpressionNode {
    this.enter();
    let left = this.parseAnd();
    while (this.peek()?.type === 'or') {
      this.pos++;
      left = { type: 'or', left, right: this.parseAnd() };
    }
    this.depth--;
    return left;
  }

  private parseAnd(): ExpressionNode {
    let left = this.parseUnary();
    while (this.peek()?.type === 'and') {
      this.pos++;
      left = { type: 'and', left, right: this.parseUnary() };
    }
    return left;
  }

  private parseUnary(): ExpressionNode {
    if (this.peek()?.type === 'not') {
      this.pos++;
      this.enter();
      const expr = this.parseUnary();
      this.depth--;
      return { type: 'not', expr };
    }
    return this.parsePrimary();
  }

  private parsePrimary(): ExpressionNode {
    const token = this.peek();
    if (!token) throw new Error('Unexpected end of expression.');
    if (token.type === 'lparen') {
      this.pos++;
      const node = this.parseOr();
      this.expect('rparen');
      return node;
    }
    if (token.type !== 'ident') throw new Error(`Unexpected "${token.value}".`);
    this.pos++;
    if (!SUPPORTED_FUNCTIONS.includes(token.value)) {
      throw new Error(
        `Unsupported function "${token.value}". Supported: ${SUPPORTED_FUNCTIONS.join(', ')}.`,
      );
    }
    const args: string[] = [];
    if (this.peek()?.type === 'lparen') {
      this.pos++;
      if (this.peek()?.type !== 'rparen') {
        args.push(this.expect('string').value);
        while (this.peek()?.type === 'comma') {
          this.pos++;
          args.push(this.expect('string').value);
        }
      }
      this.expect('rparen');
    }
    const needsArgs = token.value.startsWith('has');
    if (needsArgs && args.length === 0)
      throw new Error(`${token.value}() requires at least one quoted argument.`);
    return { type: 'call', fn: token.value, args };
  }
}
