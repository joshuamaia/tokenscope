import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { DiagnosisResult } from '../../../core/models/diagnosis.models';
import { AuthorityMappingRule } from '../../../core/models/permission.models';
import { IconComponent } from '../../../shared/components/icon/icon.component';
import { TooltipDirective } from '../../../shared/directives/tooltip.directive';
import { CONFIDENCE_HINT, CONFIDENCE_LABEL } from '../status-visuals';

@Component({
  selector: 'ts-diagnosis-summary',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent, TooltipDirective],
  template: `
    <div class="card-head">
      <div>
        <h2><ts-icon name="target" /> Diagnosis Summary</h2>
        <p class="card-sub">Causes are ranked by evidence: confirmed → likely → hypothesis.</p>
      </div>
    </div>

    @if (result().suggestedMapping; as fix) {
      <div class="fix">
        <div class="grow">
          <strong><ts-icon name="wrench" [size]="15" /> Suggested authority mapping fix</strong>
          <p class="small muted">
            Add a converter for <span class="mono">{{ fix.at(-1)?.claim }}</span> with prefix
            <span class="mono">"{{ fix.at(-1)?.prefix }}"</span> and re-run the simulation.
          </p>
        </div>
        <button type="button" class="btn btn-primary btn-sm" (click)="applyMapping.emit(fix)">
          <ts-icon name="refresh" [size]="14" /> Apply fix &amp; re-run
        </button>
      </div>
    }

    @if (result().causes.length) {
      <div class="section-label mb">Causes</div>
      <div class="causes">
        @for (cause of result().causes; track cause.id + $index; let first = $first) {
          <article
            class="cause conf-{{ cause.confidence }}"
            [class.top]="first && cause === result().mostLikely"
          >
            <header class="row-between">
              <div class="row">
                @if (first && cause === result().mostLikely) {
                  <span class="badge badge-accent">Most likely</span>
                }
                <strong>{{ cause.title }}</strong>
              </div>
              <div class="row">
                <span
                  class="badge"
                  [class.badge-info]="cause.category === 'authentication'"
                  [class.badge-warning]="cause.category === 'authorization'"
                  >{{
                    cause.category === 'authentication'
                      ? '401 · authentication'
                      : cause.category === 'authorization'
                        ? '403 · authorization'
                        : 'configuration'
                  }}</span
                >
                <span
                  class="badge conf"
                  [tsTooltip]="confidenceHint[cause.confidence]"
                  [focusable]="true"
                  >{{ confidenceLabel[cause.confidence] }}</span
                >
              </div>
            </header>
            <p>{{ cause.reason }}</p>
            @if (cause.evidence.length) {
              <ul class="ev mono">
                @for (e of cause.evidence; track $index) {
                  <li>{{ e }}</li>
                }
              </ul>
            }
            <p class="rec"><ts-icon name="lightbulb" [size]="14" /> {{ cause.recommendation }}</p>
          </article>
        }
      </div>
    } @else {
      <div class="alert alert-success">
        <ts-icon name="circle-check" [size]="16" />
        <span>No cause was confirmed by the local evidence.</span>
      </div>
    }

    @if (result().hypotheses.length) {
      <button
        type="button"
        class="hyp-toggle"
        [attr.aria-expanded]="showHypotheses()"
        (click)="showHypotheses.set(!showHypotheses())"
      >
        <ts-icon [name]="showHypotheses() ? 'chevron-down' : 'chevron-right'" [size]="15" />
        Hypotheses that need server-side investigation ({{ result().hypotheses.length }})
      </button>
      @if (showHypotheses()) {
        <div class="causes">
          @for (h of result().hypotheses; track h.id) {
            <article class="cause conf-possible">
              <header class="row-between">
                <strong>{{ h.title }}</strong>
                <span class="badge conf">Hypothesis</span>
              </header>
              <p>{{ h.reason }}</p>
              <p class="rec"><ts-icon name="lightbulb" [size]="14" /> {{ h.recommendation }}</p>
            </article>
          }
        </div>
      }
    }

    @if (recommendations().length) {
      <div class="section-label mb mt">Recommended next steps</div>
      <ol class="next">
        @for (r of recommendations(); track r) {
          <li>{{ r }}</li>
        }
      </ol>
    }
  `,
  styles: `
    :host {
      display: block;
    }
    .mb {
      margin-bottom: 8px;
    }
    .mt {
      margin-top: 16px;
    }
    .fix {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      padding: 12px 14px;
      border-radius: var(--radius);
      border: 1px dashed var(--accent);
      background: var(--accent-soft);
      margin-bottom: 14px;
      strong {
        display: flex;
        align-items: center;
        gap: 6px;
      }
    }
    .causes {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .cause {
      border: 1px solid var(--border);
      border-left: 3px solid var(--tone);
      border-radius: var(--radius);
      padding: 11px 13px;
      background: var(--surface-2);
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 0.88rem;
    }
    .cause.top {
      background: linear-gradient(
        90deg,
        color-mix(in srgb, var(--tone) 10%, var(--surface-2)),
        var(--surface-2)
      );
      box-shadow: 0 0 0 1px color-mix(in srgb, var(--tone) 35%, transparent);
    }
    .conf-confirmed {
      --tone: var(--danger);
    }
    .conf-likely {
      --tone: var(--warning);
    }
    .conf-possible {
      --tone: var(--info);
    }
    .badge.conf {
      color: var(--tone);
      background: color-mix(in srgb, var(--tone) 13%, transparent);
      cursor: help;
    }
    .ev {
      margin: 0;
      padding-left: 16px;
      font-size: 0.77rem;
      color: var(--text-muted);
      word-break: break-word;
    }
    .rec {
      display: flex;
      gap: 6px;
      align-items: flex-start;
      color: var(--text-muted);
      ts-icon {
        color: var(--warning);
        margin-top: 2px;
      }
    }
    .hyp-toggle {
      display: flex;
      align-items: center;
      gap: 6px;
      margin: 16px 0 10px;
      border: 0;
      background: none;
      color: var(--text);
      font: inherit;
      font-weight: 600;
      cursor: pointer;
      padding: 0;
    }
    .next {
      margin: 0;
      padding-left: 20px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: 0.88rem;
    }
  `,
})
export class DiagnosisSummaryComponent {
  readonly result = input.required<DiagnosisResult>();
  readonly applyMapping = output<AuthorityMappingRule[]>();
  protected readonly showHypotheses = signal(true);
  protected readonly confidenceLabel = CONFIDENCE_LABEL;
  protected readonly confidenceHint = CONFIDENCE_HINT;
  protected readonly recommendations = computed(() => this.result().recommendations.slice(0, 6));
}
