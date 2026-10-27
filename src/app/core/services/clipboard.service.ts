import { DOCUMENT, Injectable, inject } from '@angular/core';
import { ToastService } from './toast.service';

@Injectable({ providedIn: 'root' })
export class ClipboardService {
  private readonly document = inject(DOCUMENT);
  private readonly toast = inject(ToastService);

  async copy(text: string, label = 'Copied to clipboard'): Promise<boolean> {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        this.fallbackCopy(text);
      }
      this.toast.success(label);
      return true;
    } catch {
      try {
        this.fallbackCopy(text);
        this.toast.success(label);
        return true;
      } catch {
        this.toast.error('Clipboard access was denied by the browser.');
        return false;
      }
    }
  }

  /** Saves text as a local file through a Blob URL (no network involved). */
  download(text: string, filename: string): void {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = this.document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    this.toast.success(`Saved ${filename}`);
  }

  private fallbackCopy(text: string): void {
    const area = this.document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    this.document.body.appendChild(area);
    area.select();
    const ok = this.document.execCommand('copy');
    area.remove();
    if (!ok) throw new Error('copy failed');
  }
}
