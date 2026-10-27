import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  signal,
} from '@angular/core';
import { HttpMethod } from '../../../core/models/diagnosis.models';
import { JwtPayload } from '../../../core/models/jwt.models';
import { AuthorityMappingRule, ExpressionNode } from '../../../core/models/permission.models';
import { JwtPermissionService } from '../../../core/services/jwt-permission.service';
import { CopyButtonComponent } from '../../../shared/components/copy-button/copy-button.component';
import { IconComponent } from '../../../shared/components/icon/icon.component';

type Tab = 'mapping' | 'rule' | 'java' | 'concepts';

const EXAMPLES = [
  `hasRole('ADMIN')`,
  `hasAuthority('ROLE_ADMIN')`,
  `hasAuthority('SCOPE_read')`,
  `hasAnyRole('ADMIN', 'MANAGER')`,
  `hasAnyAuthority('READ', 'WRITE')`,
  `hasRole('ADMIN') and hasAuthority('SCOPE_read')`,
];

const CONCEPTS: { title: string; body: string[] }[] = [
  {
    title: 'Role vs. authority',
    body: [
      'A GrantedAuthority is any string attached to the authenticated principal. A "role" is simply an authority that follows the ROLE_ naming convention.',
      "hasAuthority('X') checks the exact string X. hasRole('X') checks the authority ROLE_X.",
    ],
  },
  {
    title: 'The ROLE_ prefix convention',
    body: [
      "hasRole('ADMIN') and hasAnyRole(...) automatically add ROLE_. The token must therefore produce ROLE_ADMIN, not ADMIN.",
      "Passing 'ROLE_ADMIN' to hasRole in authorizeHttpRequests throws IllegalArgumentException in Spring Security 6. The default prefix can be changed with a GrantedAuthorityDefaults bean.",
    ],
  },
  {
    title: 'The SCOPE_ prefix convention',
    body: [
      'With the default resource-server setup, each value in "scope" (space-delimited) or "scp" becomes an authority prefixed with SCOPE_.',
      'A token with scope "profile.read" grants SCOPE_profile.read, so the rule must be hasAuthority(\'SCOPE_profile.read\').',
    ],
  },
  {
    title: 'JwtGrantedAuthoritiesConverter',
    body: [
      'Reads one claim (authoritiesClaimName, default scope/scp), splits strings by authoritiesClaimDelimiter (default space) and prepends authorityPrefix (default SCOPE_).',
      'It only reads top-level claims: nested structures such as realm_access.roles need a custom Converter<Jwt, Collection<GrantedAuthority>>.',
    ],
  },
  {
    title: 'JwtAuthenticationConverter',
    body: [
      'Turns the validated Jwt into a JwtAuthenticationToken. Its setJwtGrantedAuthoritiesConverter(...) decides which authorities the request gets.',
      'Combining several converters (scopes + roles) requires a custom converter that merges their results.',
    ],
  },
  {
    title: 'Claim mapping',
    body: [
      'Roles in custom claims (roles, authorities, groups, realm_access.roles) are ignored unless mapped. This is the most common reason why hasRole fails although the token "contains" the role.',
    ],
  },
  {
    title: 'HTTP 401 vs. HTTP 403',
    body: [
      '401 Unauthorized: authentication failed — missing, malformed, expired, wrongly signed token, or issuer/audience mismatch (JwtDecoder/BearerTokenAuthenticationFilter).',
      '403 Forbidden: the token was accepted, but the authenticated principal lacks the required authority (AuthorizationFilter / method security), or CSRF protection rejected the request.',
    ],
  },
];

@Component({
  selector: 'ts-spring-analyzer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent, CopyButtonComponent],
  templateUrl: './spring-analyzer.component.html',
  styleUrl: './spring-analyzer.component.scss',
})
export class SpringAnalyzerComponent {
  private readonly permissions = inject(JwtPermissionService);

  readonly payload = input<JwtPayload | null>(null);
  readonly rules = input<AuthorityMappingRule[]>([]);
  readonly expression = input('');
  readonly method = input<HttpMethod>('GET');
  readonly endpoint = input('');

  protected readonly tab = signal<Tab>('mapping');
  protected readonly examples = EXAMPLES;
  protected readonly concepts = CONCEPTS;
  protected readonly openConcept = signal<number | null>(0);
  /** Editable copy of the rule; re-synced whenever the form rule changes. */
  protected readonly playground = linkedSignal(() => this.expression());

  protected readonly mapping = computed(() =>
    this.permissions.mapAuthorities(this.payload(), this.rules()),
  );
  protected readonly extracted = computed(() => this.permissions.extract(this.payload()));
  protected readonly unmapped = computed(() => {
    const used = new Set(this.mapping().traces.map((t) => t.claimUsed));
    return this.extracted().matches.filter(
      (m) => !used.has(m.path) && !(m.path === 'scp' && used.has('scope')),
    );
  });
  protected readonly evaluation = computed(() =>
    this.permissions.evaluate(this.playground(), this.mapping().authorities, 'spring'),
  );
  protected readonly interpretation = computed(() => {
    const { ast } = this.permissions.parse(this.playground());
    return ast ? this.describe(ast) : [];
  });
  protected readonly javaConfig = computed(() => this.permissions.javaConfig(this.rules()));
  protected readonly chainConfig = computed(() => this.securityChain(this.playground()));

  private describe(node: ExpressionNode): string[] {
    switch (node.type) {
      case 'and':
      case 'or':
        return [...this.describe(node.left), ...this.describe(node.right)];
      case 'not':
        return this.describe(node.expr).map((d) => `NOT ${d}`);
      case 'call': {
        const list = node.args.map((a) => `"${a}"`).join(', ');
        switch (node.fn) {
          case 'hasRole':
            return [
              `hasRole("${node.args[0]}") → requires authority "${node.args[0].startsWith('ROLE_') ? node.args[0] : 'ROLE_' + node.args[0]}"`,
            ];
          case 'hasAnyRole':
            return [
              `hasAnyRole(${list}) → requires any of ${node.args.map((a) => `"ROLE_${a.replace(/^ROLE_/, '')}"`).join(', ')}`,
            ];
          case 'hasAuthority':
            return [
              `hasAuthority("${node.args[0]}") → requires exactly "${node.args[0]}"${node.args[0].startsWith('SCOPE_') ? ` (scope "${node.args[0].slice(6)}")` : ''}`,
            ];
          case 'hasAnyAuthority':
            return [`hasAnyAuthority(${list}) → requires at least one of them, exact match`];
          case 'hasAllAuthorities':
          case 'hasAllRoles':
            return [`${node.fn}(${list}) → requires all of them`];
          default:
            return [
              `${node.fn}() → ${node.fn === 'denyAll' ? 'always denies' : node.fn === 'permitAll' ? 'always allows' : 'authentication state check'}`,
            ];
        }
      }
    }
  }

  private securityChain(expression: string): string {
    const endpoint = this.endpoint() || '/api/**';
    const { ast } = this.permissions.parse(expression);
    let rule = `.access(new WebExpressionAuthorizationManager("${expression.replace(/"/g, '\\"')}"))`;
    if (ast?.type === 'call') {
      const args = ast.args.map((a) => `"${a}"`).join(', ');
      if (['hasRole', 'hasAnyRole', 'hasAuthority', 'hasAnyAuthority'].includes(ast.fn))
        rule = `.${ast.fn}(${args})`;
      else if (ast.fn === 'permitAll' || ast.fn === 'denyAll') rule = `.${ast.fn}()`;
      else if (ast.fn === 'isAuthenticated') rule = '.authenticated()';
    }
    if (!expression.trim()) rule = '.authenticated()';
    return [
      '@Bean',
      'SecurityFilterChain api(HttpSecurity http) throws Exception {',
      '    http',
      '        .authorizeHttpRequests(auth -> auth',
      `            .requestMatchers(HttpMethod.${this.method()}, "${endpoint}")${rule}`,
      '            .anyRequest().authenticated())',
      '        .oauth2ResourceServer(oauth2 -> oauth2',
      '            .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));',
      '    return http.build();',
      '}',
    ].join('\n');
  }
}
