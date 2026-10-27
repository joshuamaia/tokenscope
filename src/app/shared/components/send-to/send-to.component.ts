import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { Router } from '@angular/router';
import { WorkspaceService } from '../../../core/services/workspace.service';
import { IconComponent, IconName } from '../icon/icon.component';

export type ToolTarget =
  | 'inspector'
  | 'troubleshooter'
  | 'security'
  | 'timeline'
  | 'compare'
  | 'permissions'
  | 'signature';

const TARGETS: { id: ToolTarget; label: string; icon: IconName; path: string }[] = [
  { id: 'troubleshooter', label: 'Diagnose', icon: 'stethoscope', path: '/troubleshooter' },
  { id: 'inspector', label: 'Inspect', icon: 'inspect', path: '/inspector' },
  { id: 'security', label: 'Analyze', icon: 'shield', path: '/security' },
  { id: 'timeline', label: 'Timeline', icon: 'clock', path: '/timeline' },
  { id: 'permissions', label: 'Permissions', icon: 'users', path: '/permissions' },
  { id: 'signature', label: 'Verify', icon: 'signature', path: '/signature' },
  { id: 'compare', label: 'Compare', icon: 'compare', path: '/compare' },
];

/** Sends the given token to other tools without re-pasting it. */
@Component({
  selector: 'ts-send-to',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  template: `
    <div class="send-to" role="group" aria-label="Send token to another tool">
      <span class="section-label">Send to</span>
      @for (t of targets(); track t.id) {
        <button
          type="button"
          class="btn btn-sm"
          [class.primary]="t.id === 'troubleshooter'"
          [disabled]="!token()"
          (click)="send(t.id)"
        >
          <ts-icon [name]="t.icon" [size]="14" /> {{ t.label }}
        </button>
      }
    </div>
  `,
  styles: `
    .send-to {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }
    .section-label {
      margin-right: 4px;
    }
    .primary {
      border-color: color-mix(in srgb, var(--accent) 55%, transparent);
      color: var(--accent-strong);
    }
  `,
})
export class SendToComponent {
  private readonly router = inject(Router);
  private readonly workspace = inject(WorkspaceService);
  readonly token = input('');
  readonly exclude = input<ToolTarget | null>(null);
  protected readonly targets = computed(() => TARGETS.filter((t) => t.id !== this.exclude()));

  send(target: ToolTarget): void {
    const token = this.token().trim();
    if (!token) return;
    this.workspace.setToken(token);
    if (target === 'troubleshooter') {
      this.workspace.troubleshooterPreset.set({ input: { token }, autoRun: false });
    }
    if (target === 'compare') {
      this.workspace.compareA.set(token);
    }
    void this.router.navigateByUrl(TARGETS.find((t) => t.id === target)!.path);
  }
}
