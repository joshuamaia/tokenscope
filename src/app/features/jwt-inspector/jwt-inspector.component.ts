import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ClaimView } from '../../core/models/jwt.models';
import { ClockService } from '../../core/services/clock.service';
import { DemoTokenService } from '../../core/services/demo-token.service';
import { HEADER_DOCS, JwtClaimsService } from '../../core/services/jwt-claims.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import { ALGORITHMS } from '../../core/services/jwt-signature.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { safeStringify } from '../../core/utils/json-path';
import { formatDateTime, formatDuration } from '../../core/utils/time-format';
import { CopyButtonComponent } from '../../shared/components/copy-button/copy-button.component';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { JsonViewerComponent } from '../../shared/components/json-viewer/json-viewer.component';
import { SendToComponent } from '../../shared/components/send-to/send-to.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';
import { TooltipDirective } from '../../shared/directives/tooltip.directive';

type Tab = 'payload' | 'header' | 'signature';

@Component({
  selector: 'ts-jwt-inspector',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    TokenInputComponent,
    JsonViewerComponent,
    CopyButtonComponent,
    IconComponent,
    SendToComponent,
    TooltipDirective,
    RouterLink,
  ],
  templateUrl: './jwt-inspector.component.html',
  styleUrl: './jwt-inspector.component.scss',
})
export class JwtInspectorComponent {
  private readonly decoder = inject(JwtDecoderService);
  private readonly claimsService = inject(JwtClaimsService);
  private readonly clock = inject(ClockService);
  private readonly demos = inject(DemoTokenService);
  private readonly router = inject(Router);
  protected readonly workspace = inject(WorkspaceService);

  protected readonly tab = signal<Tab>('payload');
  protected readonly decoded = computed(() => this.decoder.decode(this.workspace.token()));
  protected readonly hasInput = computed(() => this.workspace.token().trim().length > 0);
  protected readonly claims = computed<ClaimView[]>(() => {
    const payload = this.decoded().payload;
    return payload ? this.claimsService.describe(payload) : [];
  });
  protected readonly headerParams = computed(() =>
    Object.entries(this.decoded().header ?? {}).map(([key, value]) => ({
      key,
      value: typeof value === 'string' ? value : safeStringify(value, 0),
      doc: HEADER_DOCS[key] ?? 'Custom header parameter.',
    })),
  );
  protected readonly algSpec = computed(() => {
    const alg = this.decoded().alg;
    return alg ? (ALGORITHMS[alg] ?? null) : null;
  });
  protected readonly verification = computed(() =>
    this.workspace.verificationFor(this.workspace.token()),
  );
  protected readonly headerJson = computed(() => safeStringify(this.decoded().header));
  protected readonly payloadJson = computed(() => safeStringify(this.decoded().payload));

  async loadSample(): Promise<void> {
    const scenario = await this.demos.scenario('valid');
    this.workspace.setToken(scenario.token);
  }

  formatTime(ms: number): string {
    return formatDateTime(ms, 'local');
  }

  relative(ms: number): string {
    const diff = (ms - this.clock.tick()) / 1000;
    return diff >= 0 ? `in ${formatDuration(diff)}` : `${formatDuration(-diff)} ago`;
  }

  categoryLabel(claim: ClaimView): string {
    return claim.doc ? claim.doc.category : 'custom';
  }

  verify(): void {
    void this.router.navigateByUrl('/signature');
  }
}
