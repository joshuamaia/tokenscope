import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { ClipboardService } from '../../../core/services/clipboard.service';
import { IconComponent } from '../icon/icon.component';

@Component({
  selector: 'ts-copy-button',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  template: `
    <button
      type="button"
      class="btn btn-sm"
      [class.btn-ghost]="ghost()"
      [disabled]="!text()"
      [attr.aria-label]="label()"
      (click)="copy()"
    >
      <ts-icon [name]="copied() ? 'check' : 'copy'" [size]="14" />
      @if (showLabel()) {
        <span>{{ copied() ? 'Copied' : label() }}</span>
      }
    </button>
  `,
})
export class CopyButtonComponent {
  private readonly clipboard = inject(ClipboardService);
  readonly text = input<string>('');
  readonly label = input('Copy');
  readonly toast = input('Copied to clipboard');
  readonly showLabel = input(true);
  readonly ghost = input(false);
  protected readonly copied = signal(false);

  async copy(): Promise<void> {
    if (await this.clipboard.copy(this.text(), this.toast())) {
      this.copied.set(true);
      setTimeout(() => this.copied.set(false), 1500);
    }
  }
}
