import { Injectable, signal } from '@angular/core';
import { TroubleshooterPreset } from '../models/diagnosis.models';
import { KeyMaterial, SignatureResult } from '../models/signature.models';

export interface VerifierPreset {
  token: string;
  key: KeyMaterial;
  autoRun: boolean;
  note?: string;
}

/**
 * In-memory workspace shared by every tool (Angular Signals). Nothing here is
 * persisted: a page reload or "Clear session data" wipes all tokens and keys.
 */
@Injectable({ providedIn: 'root' })
export class WorkspaceService {
  /** The active token, shared across Inspector, Timeline, Analyzer, Permissions and Verifier. */
  readonly token = signal('');
  readonly compareA = signal('');
  readonly compareB = signal('');

  /** Last cryptographic verification executed in TokenScope (bound to the exact token). */
  readonly lastVerification = signal<{ token: string; result: SignatureResult } | null>(null);

  readonly troubleshooterPreset = signal<TroubleshooterPreset | null>(null);
  readonly verifierPreset = signal<VerifierPreset | null>(null);

  setToken(token: string): void {
    this.token.set(token.trim());
  }

  recordVerification(token: string, result: SignatureResult): void {
    this.lastVerification.set({ token: token.trim(), result });
  }

  verificationFor(token: string): SignatureResult | null {
    const last = this.lastVerification();
    return last && last.token === token.trim() ? last.result : null;
  }

  /** Reads a one-shot preset and clears it. */
  consumeTroubleshooterPreset(): TroubleshooterPreset | null {
    const preset = this.troubleshooterPreset();
    this.troubleshooterPreset.set(null);
    return preset;
  }

  consumeVerifierPreset(): VerifierPreset | null {
    const preset = this.verifierPreset();
    this.verifierPreset.set(null);
    return preset;
  }

  clear(): void {
    this.token.set('');
    this.compareA.set('');
    this.compareB.set('');
    this.lastVerification.set(null);
    this.troubleshooterPreset.set(null);
    this.verifierPreset.set(null);
  }
}
