import { ChangeDetectionStrategy, Component, inject, input, output } from '@angular/core';
import { WorkspaceService } from '../../core/services/workspace.service';
import { ThemeService } from '../../core/services/theme.service';
import { ToastService } from '../../core/services/toast.service';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { TooltipDirective } from '../../shared/directives/tooltip.directive';

@Component({
  selector: 'ts-header',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent, TooltipDirective],
  template: `
    <button
      type="button"
      class="btn btn-ghost btn-icon menu"
      aria-label="Open navigation"
      (click)="menu.emit()"
    >
      <ts-icon name="menu" />
    </button>
    <div class="title">
      <span class="crumb">TokenScope</span>
      <ts-icon name="chevron-right" [size]="14" class="sep" />
      <span class="current">{{ title() }}</span>
    </div>
    <div class="actions">
      <span
        class="local-badge"
        tsTooltip="All decoding, analysis, signing and verification run locally with Web Crypto. Nothing is uploaded or persisted."
        [focusable]="true"
      >
        <ts-icon name="shield-check" [size]="15" />
        <span class="label">Processed locally</span>
      </span>
      <button
        type="button"
        class="btn btn-ghost btn-sm"
        tsTooltip="Remove every token, key and result held in memory"
        (click)="clearSession()"
      >
        <ts-icon name="trash" [size]="15" />
        <span class="label">Clear session data</span>
      </button>
      <button
        type="button"
        class="btn btn-icon"
        [attr.aria-label]="
          theme.theme() === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
        "
        [tsTooltip]="theme.theme() === 'dark' ? 'Light mode' : 'Dark mode'"
        (click)="theme.toggle()"
      >
        <ts-icon [name]="theme.theme() === 'dark' ? 'sun' : 'moon'" [size]="17" />
      </button>
    </div>
  `,
  styles: `
    :host {
      position: sticky;
      top: 0;
      z-index: 30;
      height: var(--header-height);
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 0 24px;
      background: color-mix(in srgb, var(--bg) 82%, transparent);
      backdrop-filter: blur(10px);
      border-bottom: 1px solid var(--border);
    }
    .menu {
      display: none;
    }
    .title {
      display: flex;
      align-items: center;
      gap: 6px;
      min-width: 0;
      flex: 1;
      font-size: 0.9rem;
    }
    .crumb {
      color: var(--text-subtle);
    }
    .sep {
      color: var(--text-subtle);
    }
    .current {
      font-weight: 600;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .local-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--success);
      background: var(--success-soft);
      padding: 5px 10px;
      border-radius: 999px;
    }
    @media (max-width: 960px) {
      :host {
        padding: 0 14px;
      }
      .menu {
        display: inline-flex;
      }
      .crumb,
      .sep {
        display: none;
      }
    }
    @media (max-width: 640px) {
      .label {
        display: none;
      }
    }
  `,
})
export class HeaderComponent {
  protected readonly theme = inject(ThemeService);
  private readonly workspace = inject(WorkspaceService);
  private readonly toast = inject(ToastService);
  readonly title = input('Dashboard');
  readonly menu = output<void>();

  clearSession(): void {
    this.workspace.clear();
    this.toast.success('Session data cleared. Tokens, keys and results were removed from memory.');
  }
}
