import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { TEMPORAL_STATE_LABEL, TemporalState } from '../../core/models/timeline.models';
import { ClockService } from '../../core/services/clock.service';
import { DemoTokenService } from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import { JwtTimelineService } from '../../core/services/jwt-timeline.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import {
  TIME_ZONE_OPTIONS,
  TimeZoneMode,
  formatCountdown,
  formatDateTime,
  formatDuration,
  formatTime,
  toIso,
} from '../../core/utils/time-format';
import { IconComponent, IconName } from '../../shared/components/icon/icon.component';
import { SendToComponent } from '../../shared/components/send-to/send-to.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';
import { TooltipDirective } from '../../shared/directives/tooltip.directive';

const STATE_ICON: Record<TemporalState, IconName> = {
  valid: 'circle-check',
  expired: 'circle-x',
  'not-yet-valid': 'clock',
  'missing-exp': 'alert',
  invalid: 'circle-x',
};

const STATE_DESCRIPTION: Record<TemporalState, string> = {
  valid: 'The current time is inside the nbf/iat → exp window.',
  expired: 'The current time is past "exp". Resource servers reject expired tokens (HTTP 401).',
  'not-yet-valid':
    'The current time is before "nbf". The token cannot be used yet — often a clock-skew issue.',
  'missing-exp':
    'The token has no "exp" claim and never expires by itself. Most resource servers require it.',
  invalid: 'The temporal claims are inconsistent or malformed.',
};

@Component({
  selector: 'ts-token-timeline',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TokenInputComponent, IconComponent, SendToComponent, TooltipDirective],
  templateUrl: './token-timeline.component.html',
  styleUrl: './token-timeline.component.scss',
})
export class TokenTimelineComponent {
  private readonly decoder = inject(JwtDecoderService);
  private readonly timeline = inject(JwtTimelineService);
  private readonly clock = inject(ClockService);
  private readonly demos = inject(DemoTokenService);
  protected readonly workspace = inject(WorkspaceService);

  protected readonly zones = TIME_ZONE_OPTIONS;
  protected readonly zone = signal<TimeZoneMode>('local');
  protected readonly skew = signal(0);
  protected readonly stateLabel = TEMPORAL_STATE_LABEL;
  protected readonly stateIcon = STATE_ICON;
  protected readonly stateDescription = STATE_DESCRIPTION;

  protected readonly decoded = computed(() => this.decoder.decode(this.workspace.token()));
  protected readonly result = computed(() => {
    const decoded = this.decoded();
    return decoded.payload
      ? this.timeline.compute(decoded.payload, this.clock.tick(), this.skew())
      : null;
  });

  protected readonly rows = computed(() => {
    const r = this.result();
    if (!r) return [];
    const zone = this.zone();
    const rows = [
      { key: 'iat', label: 'Issued At (iat)', time: r.iat },
      { key: 'nbf', label: 'Not Before (nbf)', time: r.nbf },
      { key: 'now', label: 'Current Time', time: r.now },
      { key: 'exp', label: 'Expiration (exp)', time: r.exp },
    ];
    return rows.map((row) => ({
      ...row,
      formatted: row.time === null ? 'Not present' : formatDateTime(row.time, zone),
      iso: row.time === null ? '' : toIso(row.time),
      epoch: row.time === null ? '' : Math.floor(row.time / 1000).toString(),
    }));
  });

  protected readonly nowPosition = computed(
    () => this.result()?.markers.find((m) => m.key === 'now')?.position ?? 0,
  );

  async loadSample(): Promise<void> {
    this.workspace.setToken((await this.demos.scenario('valid')).token);
  }

  setSkew(value: string): void {
    const n = Number(value);
    this.skew.set(Number.isFinite(n) ? Math.min(Math.max(n, 0), 3600) : 0);
  }

  time(ms: number): string {
    return formatTime(ms, this.zone());
  }

  duration(seconds: number | null): string {
    return seconds === null ? '—' : formatDuration(seconds);
  }

  countdown(seconds: number | null): string {
    return seconds === null ? '—' : formatCountdown(seconds);
  }
}
