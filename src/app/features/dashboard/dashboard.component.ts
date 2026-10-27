import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { TEMPORAL_STATE_LABEL } from '../../core/models/timeline.models';
import { ClockService } from '../../core/services/clock.service';
import { DemoTokenService } from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import { JwtTimelineService } from '../../core/services/jwt-timeline.service';
import { ToastService } from '../../core/services/toast.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { IconComponent, IconName } from '../../shared/components/icon/icon.component';
import { MAX_TOKEN_LENGTH } from '../../core/models/jwt.models';

interface ToolCard {
  path: string;
  title: string;
  icon: IconName;
  description: string;
  action: string;
}

const TOOLS: ToolCard[] = [
  {
    path: '/inspector',
    title: 'JWT Inspector',
    icon: 'inspect',
    description:
      'Decode header, payload and signature with claim explanations and structural validation.',
    action: 'Inspect a token',
  },
  {
    path: '/security',
    title: 'Security Analyzer',
    icon: 'shield',
    description: '18 documented static rules, configurable policy and a 0–100 conformance score.',
    action: 'Analyze security',
  },
  {
    path: '/timeline',
    title: 'Token Timeline',
    icon: 'clock',
    description:
      'Visualize iat, nbf and exp with a live countdown in UTC, local or São Paulo time.',
    action: 'View timeline',
  },
  {
    path: '/compare',
    title: 'JWT Compare',
    icon: 'compare',
    description:
      'Deep JSON diff of two tokens with a smart summary of roles, scopes and expiration.',
    action: 'Compare tokens',
  },
  {
    path: '/permissions',
    title: 'Permission Explorer',
    icon: 'users',
    description: 'Roles, scopes and authorities from nested claims, plus a permission matrix.',
    action: 'Explore permissions',
  },
  {
    path: '/generator',
    title: 'JWT Generator',
    icon: 'sparkles',
    description: 'Create really signed HS256 / RS256 test tokens with locally generated keys.',
    action: 'Generate a token',
  },
  {
    path: '/signature',
    title: 'Signature Verifier',
    icon: 'signature',
    description: 'Verify HS/RS/PS/ES signatures with secrets, PEM, JWK, JWKS or a remote JWKS URL.',
    action: 'Verify a signature',
  },
];

const PREVIEW_STEPS: { title: string; status: 'passed' | 'failed' | 'not-verified' }[] = [
  { title: 'Token Structure', status: 'passed' },
  { title: 'Token Decoding', status: 'passed' },
  { title: 'Signature Verification', status: 'not-verified' },
  { title: 'Temporal Validation', status: 'passed' },
  { title: 'Claims Extraction', status: 'passed' },
  { title: 'Authority Mapping', status: 'passed' },
  { title: 'Permission Evaluation', status: 'failed' },
];

@Component({
  selector: 'ts-dashboard',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent, RouterLink],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent {
  private readonly decoder = inject(JwtDecoderService);
  private readonly timeline = inject(JwtTimelineService);
  private readonly clock = inject(ClockService);
  private readonly demos = inject(DemoTokenService);
  private readonly workspace = inject(WorkspaceService);
  private readonly router = inject(Router);
  private readonly toast = inject(ToastService);

  protected readonly tools = TOOLS;
  protected readonly previewSteps = PREVIEW_STEPS;
  protected readonly maxLength = MAX_TOKEN_LENGTH;
  protected readonly quickToken = signal(this.workspace.token());
  protected readonly loadingDemo = signal(false);

  protected readonly decoded = computed(() => this.decoder.decode(this.quickToken()));
  protected readonly indicators = computed(() => {
    const d = this.decoded();
    if (!this.quickToken().trim()) return null;
    const error = d.issues.find((i) => i.severity === 'error');
    const temporal = d.payload ? this.timeline.compute(d.payload, this.clock.tick(), 60) : null;
    return {
      structure: {
        ok: d.valid,
        label: d.valid ? 'Valid structure' : (error?.message ?? 'Invalid token'),
      },
      alg: d.alg,
      temporal: temporal
        ? { ok: temporal.state === 'valid', label: TEMPORAL_STATE_LABEL[temporal.state] }
        : null,
    };
  });

  analyze(): void {
    const token = this.quickToken().trim();
    if (!token) {
      this.toast.warning('Paste a JWT first, or try the authentication demo.');
      return;
    }
    this.workspace.setToken(token);
    this.workspace.troubleshooterPreset.set({
      input: { token, httpStatus: 'unknown', requiredRoles: '' },
      autoRun: true,
    });
    void this.router.navigateByUrl('/troubleshooter');
  }

  async tryDemo(): Promise<void> {
    this.loadingDemo.set(true);
    try {
      const scenario = await this.demos.scenario('missing-role');
      this.workspace.setToken(scenario.token);
      this.workspace.troubleshooterPreset.set(scenario.preset!);
      await this.router.navigateByUrl('/troubleshooter');
    } finally {
      this.loadingDemo.set(false);
    }
  }

  open(path: string): void {
    const token = this.quickToken().trim();
    if (token) this.workspace.setToken(token);
    void this.router.navigateByUrl(path);
  }
}
