import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ThemeService } from './core/services/theme.service';
import { ShellComponent } from './layout/shell/shell.component';

@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ShellComponent],
  template: '<ts-shell />',
})
export class App {
  // Instantiated eagerly so the stored theme is applied before first paint.
  private readonly theme = inject(ThemeService);
}
