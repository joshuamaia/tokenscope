import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  model,
  output,
} from '@angular/core';
import { MAX_TOKEN_LENGTH } from '../../../core/models/jwt.models';
import { JwtDecoderService } from '../../../core/services/jwt-decoder.service';
import { IconComponent } from '../icon/icon.component';

let nextId = 0;

/** Token textarea with live structural feedback and colorized segments. */
@Component({
  selector: 'ts-token-input',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  template: `
    <div class="field">
      <div class="row-between">
        <label [for]="id">{{ label() }}</label>
        <div class="row actions">
          @if (sampleable()) {
            <button type="button" class="btn btn-ghost btn-sm" (click)="sample.emit()">
              <ts-icon name="file" [size]="14" /> Load example
            </button>
          }
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            [disabled]="!value()"
            (click)="value.set('')"
          >
            <ts-icon name="x" [size]="14" /> Clear
          </button>
        </div>
      </div>
      <textarea
        [id]="id"
        class="textarea"
        [rows]="rows()"
        [attr.maxlength]="maxLength"
        spellcheck="false"
        autocomplete="off"
        autocapitalize="off"
        [placeholder]="placeholder()"
        [value]="value()"
        (input)="value.set($any($event.target).value)"
        [attr.aria-describedby]="id + '-status'"
      ></textarea>
      @if (showSegments() && decoded().segments; as seg) {
        <div class="segments mono" aria-label="Token segments">
          <span class="jwt-h">{{ seg.header }}</span
          >.<span class="jwt-p">{{ seg.payload }}</span
          >.<span class="jwt-s">{{ seg.signature }}</span>
        </div>
      }
      <div class="status" [id]="id + '-status'" aria-live="polite">
        @if (!value()) {
          <span class="subtle">Paste a JWT — it never leaves your browser.</span>
        } @else if (firstError(); as err) {
          <span class="bad"><ts-icon name="circle-x" [size]="14" /> {{ err }}</span>
        } @else {
          <span class="good"><ts-icon name="circle-check" [size]="14" /> Valid JWS structure</span>
          <span class="badge badge-outline mono">{{ decoded().alg }}</span>
          <span class="subtle">{{ value().length }} chars · signature not verified</span>
        }
      </div>
    </div>
  `,
  styles: `
    .actions {
      gap: 2px;
    }
    .segments {
      font-size: 0.76rem;
      line-height: 1.55;
      word-break: break-all;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 10px 12px;
      max-height: 140px;
      overflow: auto;
    }
    .status {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      font-size: 0.78rem;
      min-height: 20px;
      span {
        display: inline-flex;
        align-items: center;
        gap: 5px;
      }
    }
    .good {
      color: var(--success);
    }
    .bad {
      color: var(--danger);
    }
  `,
})
export class TokenInputComponent {
  private readonly decoder = inject(JwtDecoderService);
  readonly value = model('');
  readonly label = input('Encoded JWT');
  readonly placeholder = input('eyJhbGciOi…  (header.payload.signature)');
  readonly rows = input(4);
  readonly showSegments = input(false);
  readonly sampleable = input(false);
  readonly sample = output<void>();

  protected readonly id = `token-input-${nextId++}`;
  protected readonly maxLength = MAX_TOKEN_LENGTH;
  protected readonly decoded = computed(() => this.decoder.decode(this.value()));
  protected readonly firstError = computed(() =>
    this.value()
      ? (this.decoded().issues.find((i) => i.severity === 'error')?.message ?? null)
      : null,
  );
}
