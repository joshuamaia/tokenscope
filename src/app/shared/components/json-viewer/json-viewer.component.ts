import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { safeStringify } from '../../../core/utils/json-path';
import { tokenizeJson } from '../../../core/utils/json-tokens';

/**
 * JSON syntax highlighter. Values are rendered through text interpolation only,
 * so claim contents can never be interpreted as HTML.
 */
@Component({
  selector: 'ts-json-viewer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<pre
    class="json"
    [style.max-height]="maxHeight()"
    [attr.aria-label]="label()"
  ><code>@for (t of tokens(); track $index) {<span [class]="'t-' + t.type">{{ t.text }}</span>}</code></pre>`,
  styles: `
    .json {
      margin: 0;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 12px 14px;
      font-family: var(--font-mono);
      font-size: 0.8rem;
      line-height: 1.65;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .t-key {
      color: var(--code-key);
    }
    .t-string {
      color: var(--code-string);
    }
    .t-number {
      color: var(--code-number);
    }
    .t-boolean {
      color: var(--code-bool);
    }
    .t-null {
      color: var(--code-null);
      font-style: italic;
    }
    .t-punct,
    .t-space {
      color: var(--code-punct);
    }
  `,
})
export class JsonViewerComponent {
  readonly value = input<unknown>(null);
  readonly maxHeight = input<string>('none');
  readonly label = input<string>('JSON');
  protected readonly tokens = computed(() => tokenizeJson(safeStringify(this.value())));
}
