import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { HTTP_METHODS, HttpMethod } from '../../core/models/diagnosis.models';
import {
  AuthorityMappingRule,
  PermissionSource,
  RULE_TYPE_OPTIONS,
  RuleType,
} from '../../core/models/permission.models';
import { DemoTokenService, SPRING_DEFAULT_MAPPING } from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import {
  DEFAULT_PERMISSION_SOURCES,
  JwtPermissionService,
} from '../../core/services/jwt-permission.service';
import { ToastService } from '../../core/services/toast.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { splitList } from '../../core/utils/json-path';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { SendToComponent } from '../../shared/components/send-to/send-to.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';

interface MatrixRule {
  id: number;
  method: HttpMethod;
  endpoint: string;
  expression: string;
}

const SOURCE_PRESETS: { label: string; sources: string }[] = [
  {
    label: 'Default (all known claims)',
    sources: DEFAULT_PERMISSION_SOURCES.map((s) => `${s.path}:${s.kind}`).join('\n'),
  },
  {
    label: 'Keycloak',
    sources: 'realm_access.roles:role\nresource_access.*.roles:role\nscope:scope',
  },
  { label: 'Microsoft Entra ID', sources: 'roles:role\nscp:scope\ngroups:authority' },
  { label: 'Okta', sources: 'groups:role\nscp:scope' },
  { label: 'Auth0', sources: 'permissions:authority\nscope:scope' },
];

let nextRuleId = 1;

@Component({
  selector: 'ts-permission-explorer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TokenInputComponent, IconComponent, SendToComponent],
  templateUrl: './permission-explorer.component.html',
  styleUrl: './permission-explorer.component.scss',
})
export class PermissionExplorerComponent {
  private readonly decoder = inject(JwtDecoderService);
  private readonly permissions = inject(JwtPermissionService);
  private readonly demos = inject(DemoTokenService);
  private readonly router = inject(Router);
  private readonly toast = inject(ToastService);
  protected readonly workspace = inject(WorkspaceService);

  protected readonly methods = HTTP_METHODS;
  protected readonly ruleTypes = RULE_TYPE_OPTIONS;
  protected readonly presets = SOURCE_PRESETS;

  protected readonly sourcesText = signal(SOURCE_PRESETS[0].sources);
  protected readonly matrix = signal<MatrixRule[]>([
    {
      id: nextRuleId++,
      method: 'GET',
      endpoint: '/api/profile',
      expression: "hasAuthority('SCOPE_profile.read')",
    },
    {
      id: nextRuleId++,
      method: 'PUT',
      endpoint: '/api/profile',
      expression: "hasAuthority('SCOPE_profile.write')",
    },
    {
      id: nextRuleId++,
      method: 'GET',
      endpoint: '/api/orders',
      expression: "hasAnyRole('USER', 'ADMIN')",
    },
    {
      id: nextRuleId++,
      method: 'GET',
      endpoint: '/api/admin/users',
      expression: "hasRole('ADMIN')",
    },
    {
      id: nextRuleId++,
      method: 'DELETE',
      endpoint: '/api/admin/users/{id}',
      expression: "hasRole('ADMIN') and hasAuthority('SCOPE_admin')",
    },
  ]);

  // Simulator
  protected readonly simMethod = signal<HttpMethod>('GET');
  protected readonly simEndpoint = signal('/api/admin/users');
  protected readonly simRuleType = signal<RuleType>('hasRole');
  protected readonly simRequired = signal('ADMIN');

  protected readonly decoded = computed(() => this.decoder.decode(this.workspace.token()));
  protected readonly sources = computed<PermissionSource[]>(() =>
    this.permissions.parseSources(this.sourcesText()),
  );
  protected readonly extracted = computed(() =>
    this.permissions.extract(this.decoded().payload, this.sources()),
  );
  /** Spring naming convention used for simulations: ROLE_<role>, SCOPE_<scope>, authorities unchanged. */
  protected readonly authorities = computed(() => {
    const e = this.extracted();
    return [
      ...new Set([
        ...e.roles.map((r) => (r.startsWith('ROLE_') ? r : `ROLE_${r}`)),
        ...e.scopes.map((s) => (s.startsWith('SCOPE_') ? s : `SCOPE_${s}`)),
        ...e.authorities,
      ]),
    ];
  });
  protected readonly matrixResults = computed(() =>
    this.matrix().map((rule) => ({
      rule,
      evaluation: this.permissions.evaluate(rule.expression, this.authorities(), 'spring'),
    })),
  );
  protected readonly simExpression = computed(() =>
    this.expressionFor(this.simRuleType(), splitList(this.simRequired())),
  );
  protected readonly simulation = computed(() =>
    this.permissions.evaluate(this.simExpression(), this.authorities(), 'spring'),
  );

  async loadSample(): Promise<void> {
    this.workspace.setToken((await this.demos.scenario('valid')).token);
  }

  applyPreset(index: string): void {
    const preset = SOURCE_PRESETS[Number(index)];
    if (preset) this.sourcesText.set(preset.sources);
  }

  addRule(method: string, endpoint: string, expression: string): void {
    if (!expression.trim()) {
      this.toast.warning("Enter a rule expression, e.g. hasRole('ADMIN').");
      return;
    }
    this.matrix.update((rows) => [
      ...rows,
      {
        id: nextRuleId++,
        method: method as HttpMethod,
        endpoint: endpoint.trim() || '/',
        expression: expression.trim(),
      },
    ]);
  }

  removeRule(id: number): void {
    this.matrix.update((rows) => rows.filter((r) => r.id !== id));
  }

  openInTroubleshooter(
    method: HttpMethod,
    endpoint: string,
    ruleType: RuleType,
    required: string[],
    customExpression = '',
  ): void {
    const token = this.workspace.token();
    if (!token) {
      this.toast.warning('Load a token first.');
      return;
    }
    const roleRule = ruleType === 'hasRole' || ruleType === 'hasAnyRole';
    this.workspace.troubleshooterPreset.set({
      label: 'Rule from Permission Explorer',
      autoRun: true,
      input: {
        token,
        httpStatus: '403',
        method,
        endpoint,
        ruleType,
        requiredRoles: roleRule ? required.join(', ') : '',
        requiredScopes: '',
        requiredAuthorities: roleRule ? '' : required.join(', '),
        customExpression,
        springMode: true,
        mappingRules: this.mappingFromSources(),
        signatureMode: 'skip',
        expectedIssuer: '',
        expectedAudience: '',
      },
    });
    void this.router.navigateByUrl('/troubleshooter');
  }

  openSimulation(): void {
    this.openInTroubleshooter(
      this.simMethod(),
      this.simEndpoint(),
      this.simRuleType(),
      splitList(this.simRequired()),
    );
  }

  openMatrixRule(rule: MatrixRule): void {
    this.openInTroubleshooter(rule.method, rule.endpoint, 'hasAuthority', [], rule.expression);
  }

  /** Converters equivalent to the Spring naming convention used here, for the detected claims. */
  private mappingFromSources(): AuthorityMappingRule[] {
    const rules: AuthorityMappingRule[] = [];
    for (const match of this.extracted().matches) {
      if (match.kind === 'scope') {
        if (!rules.some((r) => r.claim === 'scope|scp')) rules.push(...SPRING_DEFAULT_MAPPING);
      } else if (!rules.some((r) => r.claim === match.path)) {
        const prefixed = match.values.every((v) => v.startsWith('ROLE_'));
        rules.push({
          claim: match.path,
          prefix: match.kind === 'role' && !prefixed ? 'ROLE_' : '',
          delimiter: ' ',
        });
      }
    }
    return rules.length ? rules : [...SPRING_DEFAULT_MAPPING];
  }

  private expressionFor(ruleType: RuleType, values: string[]): string {
    const roleRule = ruleType === 'hasRole' || ruleType === 'hasAnyRole';
    return this.permissions.buildExpression(
      { ruleType, roles: roleRule ? values : [], scopes: [], authorities: roleRule ? [] : values },
      true,
    );
  }
}
