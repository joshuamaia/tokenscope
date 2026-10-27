import { ChangeDetectionStrategy, Component, effect, input, signal } from '@angular/core';
import { DiagnosticStep, STEP_STATUS_LABEL, StepId } from '../../../core/models/diagnosis.models';
import { IconComponent } from '../../../shared/components/icon/icon.component';
import { STEP_ICON } from '../status-visuals';

/** Vertical, progressively-disclosed pipeline of diagnostic steps. */
@Component({
  selector: 'ts-diagnosis-pipeline',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  templateUrl: './diagnosis-pipeline.component.html',
  styleUrl: './diagnosis-pipeline.component.scss',
})
export class DiagnosisPipelineComponent {
  readonly steps = input.required<DiagnosticStep[]>();
  /** Step opened automatically after each run (usually the first failure). */
  readonly focus = input<StepId | null>(null);

  protected readonly expanded = signal<ReadonlySet<StepId>>(new Set());
  protected readonly icon = STEP_ICON;
  protected readonly label = STEP_STATUS_LABEL;

  constructor() {
    effect(() => {
      const focus = this.focus();
      this.steps();
      this.expanded.set(new Set(focus ? [focus] : []));
    });
  }

  toggle(id: StepId): void {
    this.expanded.update((set) => {
      const next = new Set(set);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  expandAll(open: boolean): void {
    this.expanded.set(new Set(open ? this.steps().map((s) => s.id) : []));
  }
}
