import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { NAV_ITEMS } from '../navigation';

@Component({
  selector: 'ts-sidebar',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive, IconComponent],
  host: { '[class.open]': 'open()' },
  template: `
    <div class="brand">
      <div class="logo"><ts-icon name="logo" [size]="20" /></div>
      <div>
        <div class="brand-name">TokenScope</div>
        <div class="brand-tag">JWT security toolkit</div>
      </div>
      <button
        type="button"
        class="btn btn-ghost btn-icon close"
        aria-label="Close navigation"
        (click)="navigate.emit()"
      >
        <ts-icon name="x" />
      </button>
    </div>

    <nav aria-label="Main navigation">
      @for (item of items; track item.path) {
        <a
          [routerLink]="item.path"
          routerLinkActive="active"
          [routerLinkActiveOptions]="{ exact: item.path === '/' }"
          class="nav-item"
          [class.highlight]="item.highlight"
          [attr.title]="item.description"
          (click)="navigate.emit()"
        >
          <ts-icon [name]="item.icon" [size]="18" />
          <span class="grow">{{ item.label }}</span>
          @if (item.highlight) {
            <span class="core-tag">Core</span>
          }
        </a>
      }
    </nav>

    <div class="privacy">
      <ts-icon name="lock" [size]="16" />
      <span>Your tokens are processed locally in your browser.</span>
    </div>
  `,
  styleUrl: './sidebar.component.scss',
})
export class SidebarComponent {
  readonly open = input(false);
  readonly navigate = output<void>();
  protected readonly items = NAV_ITEMS;
}
