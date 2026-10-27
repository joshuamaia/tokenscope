import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import {
  DEMO_AUDIENCE,
  DEMO_ISSUER,
  DEMO_SECRET,
  DemoId,
  DemoTokenService,
} from '../../core/services/demo-token.service';
import { ToastService } from '../../core/services/toast.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { IconComponent, IconName } from '../../shared/components/icon/icon.component';

interface DemoCard {
  id: DemoId;
  number: number;
  title: string;
  icon: IconName;
  tone: 'success' | 'danger' | 'warning' | 'info' | 'accent';
  description: string;
  expected: string;
  primary: { label: string; action: DemoAction };
  secondary?: { label: string; action: DemoAction };
  featured?: boolean;
}

type DemoAction = 'inspector' | 'timeline' | 'troubleshooter' | 'security' | 'verifier' | 'compare';

const DEMOS: DemoCard[] = [
  {
    id: 'missing-role',
    number: 3,
    title: 'HTTP 403: Missing Role',
    icon: 'shield-alert',
    tone: 'danger',
    featured: true,
    description:
      'Token with ROLE_USER calls GET /api/admin/users, which requires ROLE_ADMIN. Full 10-step pipeline with Spring Security mapping.',
    expected: 'Access Denied — Simulated · Missing Required Authority',
    primary: { label: 'Run diagnosis', action: 'troubleshooter' },
  },
  {
    id: 'valid',
    number: 1,
    title: 'Valid JWT',
    icon: 'circle-check',
    tone: 'success',
    description:
      'A temporally valid HS256 token with roles and scopes. Explore decoding, claims and the live timeline.',
    expected: 'Within Validity Window',
    primary: { label: 'Open in Inspector', action: 'inspector' },
    secondary: { label: 'Timeline', action: 'timeline' },
  },
  {
    id: 'expired',
    number: 2,
    title: 'Expired JWT',
    icon: 'clock',
    tone: 'warning',
    description:
      'Token expired 45 minutes ago. See how the Troubleshooter proves the 401 cause and how the Security Analyzer scores it.',
    expected: 'HTTP 401 · JWT Expired (confirmed)',
    primary: { label: 'Run diagnosis', action: 'troubleshooter' },
    secondary: { label: 'Security Analyzer', action: 'security' },
  },
  {
    id: 'missing-scope',
    number: 4,
    title: 'HTTP 403: Missing Scope',
    icon: 'target',
    tone: 'danger',
    description:
      'Token with SCOPE_profile.read calls PUT /api/profile, which requires SCOPE_profile.write.',
    expected: 'Access Denied — Simulated · Insufficient Scope',
    primary: { label: 'Run diagnosis', action: 'troubleshooter' },
  },
  {
    id: 'invalid-signature',
    number: 5,
    title: 'Invalid Signature',
    icon: 'signature',
    tone: 'danger',
    description:
      'The payload was edited after signing (USER → ADMIN). Verified for real against the demo HS256 key.',
    expected: 'Invalid Signature',
    primary: { label: 'Verify signature', action: 'verifier' },
    secondary: { label: 'Diagnose 401', action: 'troubleshooter' },
  },
  {
    id: 'compare',
    number: 6,
    title: 'JWT Comparison',
    icon: 'compare',
    tone: 'info',
    description:
      'Two tokens with different roles, scopes, issuers and expirations, opened side by side.',
    expected: 'Token B contains ROLE_ADMIN, which is missing from Token A.',
    primary: { label: 'Open comparison', action: 'compare' },
  },
  {
    id: 'spring-mapping',
    number: 7,
    title: 'Spring Security Authority Mapping',
    icon: 'server',
    tone: 'accent',
    description:
      'Token has roles: ["ADMIN"], but the default converter only maps scope/scp. hasRole("ADMIN") fails — then apply the suggested mapping fix and re-run.',
    expected: 'Permission Claim Not Mapped → fix → Access Granted — Simulated',
    primary: { label: 'Run diagnosis', action: 'troubleshooter' },
  },
];

@Component({
  selector: 'ts-demo-playground',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  templateUrl: './demo-playground.component.html',
  styleUrl: './demo-playground.component.scss',
})
export class DemoPlaygroundComponent {
  private readonly demos = inject(DemoTokenService);
  private readonly workspace = inject(WorkspaceService);
  private readonly router = inject(Router);
  private readonly toast = inject(ToastService);

  protected readonly cards = DEMOS;
  protected readonly loading = signal<string | null>(null);
  protected readonly secret = DEMO_SECRET;
  protected readonly issuer = DEMO_ISSUER;
  protected readonly audience = DEMO_AUDIENCE;

  async run(card: DemoCard, action: DemoAction): Promise<void> {
    this.loading.set(`${card.id}:${action}`);
    try {
      const scenario = await this.demos.scenario(card.id);
      this.workspace.setToken(scenario.token);
      switch (action) {
        case 'inspector':
          await this.router.navigateByUrl('/inspector');
          break;
        case 'timeline':
          await this.router.navigateByUrl('/timeline');
          break;
        case 'security':
          await this.router.navigateByUrl('/security');
          break;
        case 'compare':
          this.workspace.compareA.set(scenario.token);
          this.workspace.compareB.set(scenario.tokenB ?? '');
          await this.router.navigateByUrl('/compare');
          break;
        case 'verifier':
          this.workspace.verifierPreset.set({
            token: scenario.token,
            key: { type: 'secret', value: DEMO_SECRET, encoding: 'utf8' },
            autoRun: true,
            note: 'Demo 5: the payload was modified after signing (roles escalated to ADMIN). Verifying with the demo HS256 test key.',
          });
          await this.router.navigateByUrl('/signature');
          break;
        case 'troubleshooter':
          if (scenario.preset) this.workspace.troubleshooterPreset.set(scenario.preset);
          await this.router.navigateByUrl('/troubleshooter');
          break;
      }
    } catch (e) {
      this.toast.error(`Could not load the demo: ${(e as Error).message}`);
    } finally {
      this.loading.set(null);
    }
  }
}
