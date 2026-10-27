import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

@Component({
  selector: 'ts-score-gauge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <svg
      viewBox="0 0 120 120"
      role="img"
      [attr.aria-label]="'Security score ' + score() + ' out of 100'"
    >
      <circle cx="60" cy="60" r="50" class="track" />
      <circle
        cx="60"
        cy="60"
        r="50"
        class="value"
        [style.stroke]="color()"
        [attr.stroke-dasharray]="circumference"
        [attr.stroke-dashoffset]="offset()"
      />
      <text x="60" y="58" text-anchor="middle" class="score">{{ score() }}</text>
      <text x="60" y="78" text-anchor="middle" class="label">{{ label() }}</text>
    </svg>
  `,
  styles: `
    :host {
      display: inline-block;
      width: 150px;
      height: 150px;
    }
    svg {
      width: 100%;
      height: 100%;
      transform: rotate(0deg);
    }
    circle {
      fill: none;
      stroke-width: 10;
    }
    .track {
      stroke: var(--surface-3);
    }
    .value {
      stroke-linecap: round;
      transform: rotate(-90deg);
      transform-origin: 60px 60px;
      transition: stroke-dashoffset 0.8s ease;
    }
    .score {
      font-size: 30px;
      font-weight: 750;
      fill: var(--text);
    }
    .label {
      font-size: 10px;
      fill: var(--text-muted);
      letter-spacing: 0.04em;
    }
  `,
})
export class ScoreGaugeComponent {
  readonly score = input(0);
  readonly label = input('Security Score');
  protected readonly circumference = 2 * Math.PI * 50;
  protected readonly offset = computed(
    () => this.circumference * (1 - Math.max(0, Math.min(100, this.score())) / 100),
  );
  protected readonly color = computed(() => {
    const s = this.score();
    return s >= 90
      ? 'var(--success)'
      : s >= 75
        ? 'var(--info)'
        : s >= 60
          ? 'var(--warning)'
          : s >= 40
            ? 'var(--sev-high)'
            : 'var(--danger)';
  });
}
