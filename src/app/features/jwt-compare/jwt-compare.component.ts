import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { DemoTokenService } from '../../core/services/demo-token.service';
import { JwtCompareService } from '../../core/services/jwt-compare.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { DiffKind } from '../../core/utils/deep-diff';
import { safeStringify } from '../../core/utils/json-path';
import { CopyButtonComponent } from '../../shared/components/copy-button/copy-button.component';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { JsonViewerComponent } from '../../shared/components/json-viewer/json-viewer.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';

type Tab = 'differences' | 'summary' | 'json';

@Component({
  selector: 'ts-jwt-compare',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TokenInputComponent, IconComponent, CopyButtonComponent, JsonViewerComponent],
  templateUrl: './jwt-compare.component.html',
  styleUrl: './jwt-compare.component.scss',
})
export class JwtCompareComponent {
  private readonly decoder = inject(JwtDecoderService);
  private readonly compareService = inject(JwtCompareService);
  private readonly demos = inject(DemoTokenService);
  protected readonly workspace = inject(WorkspaceService);

  protected readonly tab = signal<Tab>('differences');
  protected readonly showUnchanged = signal(false);

  protected readonly a = computed(() => this.decoder.decode(this.workspace.compareA()));
  protected readonly b = computed(() => this.decoder.decode(this.workspace.compareB()));
  protected readonly ready = computed(() => this.a().decoded && this.b().decoded);
  protected readonly result = computed(() =>
    this.ready() ? this.compareService.compare(this.a(), this.b()) : null,
  );
  protected readonly rows = computed(() => {
    const r = this.result();
    if (!r) return [];
    const all = [
      ...r.header.map((d) => ({ ...d, section: 'header' })),
      ...r.payload.map((d) => ({ ...d, section: 'payload' })),
    ];
    return this.showUnchanged() ? all : all.filter((d) => d.kind !== 'unchanged');
  });
  protected readonly report = computed(() => {
    const r = this.result();
    return r ? this.compareService.report(r) : '';
  });

  async loadDemo(): Promise<void> {
    const scenario = await this.demos.scenario('compare');
    this.workspace.compareA.set(scenario.token);
    this.workspace.compareB.set(scenario.tokenB ?? '');
  }

  swap(): void {
    const a = this.workspace.compareA();
    this.workspace.compareA.set(this.workspace.compareB());
    this.workspace.compareB.set(a);
  }

  useActive(target: 'A' | 'B'): void {
    (target === 'A' ? this.workspace.compareA : this.workspace.compareB).set(
      this.workspace.token(),
    );
  }

  value(v: unknown): string {
    return v === undefined ? '' : safeStringify(v, 0);
  }

  kindLabel(kind: DiffKind): string {
    return kind.charAt(0).toUpperCase() + kind.slice(1);
  }
}
