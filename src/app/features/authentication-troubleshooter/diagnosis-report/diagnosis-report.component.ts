import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';
import { DiagnosisResult } from '../../../core/models/diagnosis.models';
import { JwtPayload } from '../../../core/models/jwt.models';
import { ClipboardService } from '../../../core/services/clipboard.service';
import { JwtTroubleshooterService } from '../../../core/services/jwt-troubleshooter.service';
import { IconComponent } from '../../../shared/components/icon/icon.component';

@Component({
  selector: 'ts-diagnosis-report',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  template: `
    <div class="card-head">
      <div>
        <h2><ts-icon name="file" /> Diagnosis Report</h2>
        <p class="card-sub">
          Plain-text report for tickets and pull requests. The raw JWT, signature and keys are
          always omitted.
        </p>
      </div>
    </div>
    <div class="row-between">
      <label class="switch">
        <input
          type="checkbox"
          [checked]="includeClaims()"
          (change)="includeClaims.set($any($event.target).checked)"
        />
        Include decoded claims (may contain personal data)
      </label>
      <div class="row">
        <button
          type="button"
          class="btn btn-ghost btn-sm"
          (click)="showPreview.set(!showPreview())"
        >
          <ts-icon name="eye" [size]="14" /> {{ showPreview() ? 'Hide' : 'Preview' }}
        </button>
        <button type="button" class="btn btn-sm" (click)="download()">
          <ts-icon name="download" [size]="14" /> Download .txt
        </button>
        <button type="button" class="btn btn-primary btn-sm" (click)="copy()">
          <ts-icon name="copy" [size]="14" /> Copy Diagnosis Report
        </button>
      </div>
    </div>
    @if (showPreview()) {
      <pre class="code-block preview">{{ report() }}</pre>
    }
  `,
  styles: `
    :host {
      display: block;
    }
    .preview {
      margin-top: 12px;
      max-height: 420px;
      white-space: pre-wrap;
    }
  `,
})
export class DiagnosisReportComponent {
  private readonly troubleshooter = inject(JwtTroubleshooterService);
  private readonly clipboard = inject(ClipboardService);

  readonly result = input.required<DiagnosisResult>();
  readonly claims = input<JwtPayload | null>(null);
  protected readonly includeClaims = signal(false);
  protected readonly showPreview = signal(false);

  protected readonly report = computed(() =>
    this.troubleshooter.buildReport(this.result(), {
      includeClaims: this.includeClaims(),
      claims: this.claims(),
    }),
  );

  copy(): void {
    void this.clipboard.copy(this.report(), 'Diagnosis report copied');
  }

  download(): void {
    const stamp = new Date(this.result().analyzedAt).toISOString().replace(/[:.]/g, '-');
    this.clipboard.download(this.report(), `tokenscope-diagnosis-${stamp}.txt`);
  }
}
