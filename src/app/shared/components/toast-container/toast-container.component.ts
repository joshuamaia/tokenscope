import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ToastService, ToastTone } from '../../../core/services/toast.service';
import { IconComponent, IconName } from '../icon/icon.component';

const TONE_ICON: Record<ToastTone, IconName> = {
  success: 'circle-check',
  error: 'circle-x',
  info: 'info',
  warning: 'alert',
};

@Component({
  selector: 'ts-toast-container',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  template: `
    <div class="toasts" role="status" aria-live="polite">
      @for (toast of toasts.toasts(); track toast.id) {
        <div class="toast" [class]="'toast toast-' + toast.tone">
          <ts-icon [name]="icon[toast.tone]" [size]="17" />
          <span class="grow">{{ toast.message }}</span>
          <button
            type="button"
            class="close"
            aria-label="Dismiss notification"
            (click)="toasts.dismiss(toast.id)"
          >
            <ts-icon name="x" [size]="14" />
          </button>
        </div>
      }
    </div>
  `,
  styles: `
    .toasts {
      position: fixed;
      right: 20px;
      bottom: 20px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      z-index: 1000;
      max-width: min(380px, calc(100vw - 40px));
    }
    .toast {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 11px 12px 11px 14px;
      background: var(--surface);
      border: 1px solid var(--border-strong);
      border-left: 3px solid var(--tone);
      border-radius: var(--radius);
      box-shadow: var(--shadow-lg);
      animation: pop-in 0.2s ease;
      font-size: 0.88rem;
      > ts-icon {
        color: var(--tone);
      }
    }
    .toast-success {
      --tone: var(--success);
    }
    .toast-error {
      --tone: var(--danger);
    }
    .toast-info {
      --tone: var(--info);
    }
    .toast-warning {
      --tone: var(--warning);
    }
    .close {
      border: 0;
      background: transparent;
      color: var(--text-subtle);
      cursor: pointer;
      display: grid;
      place-items: center;
      padding: 2px;
    }
  `,
})
export class ToastContainerComponent {
  protected readonly toasts = inject(ToastService);
  protected readonly icon = TONE_ICON;
}
