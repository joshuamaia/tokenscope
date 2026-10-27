import { Directive, input } from '@angular/core';

/**
 * Lightweight accessible tooltip: renders through the global `[data-tip]` CSS
 * (text only, never HTML) and exposes the text to assistive technologies.
 */
@Directive({
  selector: '[tsTooltip]',
  host: {
    '[attr.data-tip]': 'tsTooltip() || null',
    '[attr.data-tip-pos]': 'tooltipPosition() === "top" ? null : tooltipPosition()',
    '[attr.aria-label]': 'ariaLabel() ?? tsTooltip()',
    '[attr.tabindex]': 'focusable() ? 0 : null',
  },
})
export class TooltipDirective {
  readonly tsTooltip = input<string | null | undefined>('');
  readonly tooltipPosition = input<'top' | 'right'>('top');
  readonly ariaLabel = input<string | null>(null);
  readonly focusable = input(false);
}
