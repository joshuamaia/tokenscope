import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, NavigationEnd, Router, RouterOutlet } from '@angular/router';
import { filter, map } from 'rxjs';
import { ToastContainerComponent } from '../../shared/components/toast-container/toast-container.component';
import { HeaderComponent } from '../header/header.component';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'ts-shell',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, SidebarComponent, HeaderComponent, ToastContainerComponent],
  template: `
    <a class="skip" href="#main">Skip to content</a>
    <ts-sidebar [open]="menuOpen()" (navigate)="menuOpen.set(false)" />
    @if (menuOpen()) {
      <div class="backdrop" (click)="menuOpen.set(false)" aria-hidden="true"></div>
    }
    <div class="main-area">
      <ts-header [title]="title()" (menu)="menuOpen.set(true)" />
      <main id="main" tabindex="-1">
        <router-outlet />
      </main>
      <footer>
        TokenScope — static analysis and simulations run entirely in your browser. Simulated results
        do not guarantee how a real server will behave.
      </footer>
    </div>
    <ts-toast-container />
  `,
  styles: `
    :host {
      display: block;
      min-height: 100dvh;
    }
    .main-area {
      margin-left: var(--sidebar-width);
      min-height: 100dvh;
      display: flex;
      flex-direction: column;
    }
    main {
      flex: 1;
      padding: 24px;
      outline: none;
    }
    footer {
      padding: 14px 24px 22px;
      color: var(--text-subtle);
      font-size: 0.75rem;
      text-align: center;
    }
    .backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.5);
      z-index: 35;
    }
    .skip {
      position: absolute;
      left: -9999px;
      &:focus {
        left: 12px;
        top: 12px;
        z-index: 100;
        background: var(--surface);
        padding: 8px 12px;
        border-radius: var(--radius);
      }
    }
    @media (max-width: 960px) {
      .main-area {
        margin-left: 0;
      }
      main {
        padding: 16px;
      }
    }
  `,
})
export class ShellComponent {
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  protected readonly menuOpen = signal(false);

  protected readonly title = toSignal(
    this.router.events.pipe(
      filter((e) => e instanceof NavigationEnd),
      map(() => {
        let r = this.route.snapshot;
        while (r.firstChild) r = r.firstChild;
        return (r.data['title'] as string | undefined) ?? 'Dashboard';
      }),
    ),
    { initialValue: 'Dashboard' },
  );
}
