import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import {
  SEVERITY_ORDER,
  SEVERITY_PENALTY,
  SecurityPolicy,
  Severity,
} from '../../core/models/security.models';
import { DemoTokenService } from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import {
  DEFAULT_SECURITY_POLICY,
  JwtSecurityAnalyzerService,
  SECURITY_RULES,
} from '../../core/services/jwt-security-analyzer.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { splitList } from '../../core/utils/json-path';
import { IconComponent, IconName } from '../../shared/components/icon/icon.component';
import { ScoreGaugeComponent } from '../../shared/components/score-gauge/score-gauge.component';
import { SendToComponent } from '../../shared/components/send-to/send-to.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';

const SEVERITY_ICON: Record<Severity, IconName> = {
  critical: 'shield-alert',
  high: 'alert',
  medium: 'alert',
  low: 'info',
  info: 'info',
};

@Component({
  selector: 'ts-security-analyzer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TokenInputComponent, IconComponent, ScoreGaugeComponent, SendToComponent],
  templateUrl: './security-analyzer.component.html',
  styleUrl: './security-analyzer.component.scss',
})
export class SecurityAnalyzerComponent {
  private readonly decoder = inject(JwtDecoderService);
  private readonly analyzer = inject(JwtSecurityAnalyzerService);
  private readonly demos = inject(DemoTokenService);
  protected readonly workspace = inject(WorkspaceService);

  protected readonly severities = SEVERITY_ORDER;
  protected readonly penalty = SEVERITY_PENALTY;
  protected readonly severityIcon = SEVERITY_ICON;
  protected readonly rules = SECURITY_RULES;

  protected readonly policy = signal<SecurityPolicy>({ ...DEFAULT_SECURITY_POLICY });
  protected readonly expanded = signal<string | null>(null);
  protected readonly showPolicy = signal(false);
  protected readonly filter = signal<Severity | null>(null);

  protected readonly decoded = computed(() => this.decoder.decode(this.workspace.token()));
  protected readonly report = computed(() =>
    this.decoded().decoded ? this.analyzer.analyze(this.decoded(), this.policy()) : null,
  );
  protected readonly visibleFindings = computed(() => {
    const f = this.filter();
    return (this.report()?.findings ?? []).filter((x) => !f || x.severity === f);
  });

  async loadSample(kind: 'valid' | 'expired' = 'expired'): Promise<void> {
    this.workspace.setToken((await this.demos.scenario(kind)).token);
  }

  updatePolicy(patch: Partial<SecurityPolicy>): void {
    this.policy.update((p) => ({ ...p, ...patch }));
  }

  setMaxLifetime(value: string): void {
    const n = Math.round(Number(value));
    if (Number.isFinite(n) && n > 0 && n <= 525600) this.updatePolicy({ maxLifetimeMinutes: n });
  }

  setSkew(value: string): void {
    const n = Math.round(Number(value));
    if (Number.isFinite(n) && n >= 0 && n <= 3600) this.updatePolicy({ clockSkewSeconds: n });
  }

  setList(key: 'requiredClaims' | 'allowedAlgorithms', value: string): void {
    this.updatePolicy({ [key]: splitList(value) });
  }

  resetPolicy(): void {
    this.policy.set({ ...DEFAULT_SECURITY_POLICY });
  }

  toggle(id: string): void {
    this.expanded.update((current) => (current === id ? null : id));
  }

  toggleFilter(severity: Severity): void {
    this.filter.update((f) => (f === severity ? null : severity));
  }
}
