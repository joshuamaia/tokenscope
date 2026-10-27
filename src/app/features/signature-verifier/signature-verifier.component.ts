import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  KeyMaterial,
  SecretEncoding,
  SignatureResult,
  SignatureStatus,
} from '../../core/models/signature.models';
import { DEMO_SECRET, DemoTokenService } from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import {
  ALGORITHMS,
  JwtSignatureService,
  SUPPORTED_ALGORITHMS,
} from '../../core/services/jwt-signature.service';
import { ToastService } from '../../core/services/toast.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { IconComponent, IconName } from '../../shared/components/icon/icon.component';
import { SendToComponent } from '../../shared/components/send-to/send-to.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';

type KeyTab = 'secret' | 'pem' | 'jwk' | 'jwks' | 'remote';

const STATUS_ICON: Record<SignatureStatus, IconName> = {
  verified: 'shield-check',
  invalid: 'shield-alert',
  'not-verified': 'circle-help',
  unsupported: 'circle-minus',
  error: 'alert',
};

@Component({
  selector: 'ts-signature-verifier',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TokenInputComponent, IconComponent, SendToComponent, RouterLink],
  templateUrl: './signature-verifier.component.html',
  styleUrl: './signature-verifier.component.scss',
})
export class SignatureVerifierComponent implements OnInit {
  private readonly decoder = inject(JwtDecoderService);
  private readonly signature = inject(JwtSignatureService);
  private readonly demos = inject(DemoTokenService);
  private readonly toast = inject(ToastService);
  protected readonly workspace = inject(WorkspaceService);

  protected readonly supported = SUPPORTED_ALGORITHMS;
  protected readonly statusIcon = STATUS_ICON;

  protected readonly tab = signal<KeyTab>('secret');
  protected readonly secret = signal('');
  protected readonly encoding = signal<SecretEncoding>('utf8');
  protected readonly revealSecret = signal(false);
  protected readonly pem = signal('');
  protected readonly jwk = signal('');
  protected readonly jwks = signal('');
  protected readonly remoteUrl = signal('');
  protected readonly remoteJwks = signal<string | null>(null);
  protected readonly remoteInfo = signal<string | null>(null);
  protected readonly fetching = signal(false);
  protected readonly verifying = signal(false);
  protected readonly result = signal<SignatureResult | null>(null);
  protected readonly note = signal<string | null>(null);

  protected readonly decoded = computed(() => this.decoder.decode(this.workspace.token()));
  protected readonly alg = computed(() => this.decoded().alg);
  protected readonly algSpec = computed(() => {
    const alg = this.alg();
    return alg ? (ALGORITHMS[alg] ?? null) : null;
  });
  protected readonly kid = computed(() => {
    const kid = this.decoded().header?.['kid'];
    return typeof kid === 'string' ? kid : null;
  });
  protected readonly tokenKeyRefs = computed(() =>
    ['jku', 'x5u', 'jwk'].filter((p) => this.decoded().header && p in this.decoded().header!),
  );
  /** Result is only shown while it still belongs to the token in the editor. */
  protected readonly currentResult = computed(() => {
    const result = this.result();
    return result && this.workspace.verificationFor(this.workspace.token()) === result
      ? result
      : null;
  });

  ngOnInit(): void {
    const preset = this.workspace.consumeVerifierPreset();
    if (preset) {
      this.workspace.setToken(preset.token);
      this.applyKey(preset.key);
      this.note.set(preset.note ?? null);
      if (preset.autoRun) void this.verify();
      return;
    }
    const spec = this.algSpec();
    if (spec && spec.kty !== 'oct') this.tab.set('pem');
  }

  async loadSample(): Promise<void> {
    const scenario = await this.demos.scenario('invalid-signature');
    this.workspace.setToken(scenario.token);
    this.applyKey({ type: 'secret', value: DEMO_SECRET, encoding: 'utf8' });
    this.note.set(
      'Demo token: the payload was modified after signing (roles escalated to ADMIN). The demo HS256 test secret is preloaded.',
    );
    this.result.set(null);
  }

  async verify(): Promise<void> {
    const key = this.keyMaterial();
    if (!key) {
      this.toast.warning('Provide a key first.');
      return;
    }
    this.verifying.set(true);
    try {
      const token = this.workspace.token();
      const result = await this.signature.verify(token, key);
      this.workspace.recordVerification(token, result);
      this.result.set(result);
    } finally {
      this.verifying.set(false);
    }
  }

  async fetchRemote(): Promise<void> {
    this.fetching.set(true);
    this.remoteInfo.set(null);
    this.remoteJwks.set(null);
    const result = await this.signature.fetchJwks(this.remoteUrl());
    this.fetching.set(false);
    if (result.ok && result.json) {
      this.remoteJwks.set(result.json);
      this.remoteInfo.set(`Loaded ${result.keyCount} key(s) from ${new URL(result.url).host}.`);
      this.toast.success('JWKS downloaded');
    } else {
      this.remoteInfo.set(result.error ?? 'Unknown error');
      this.toast.error('Could not download the JWKS');
    }
  }

  clearKeys(): void {
    this.secret.set('');
    this.pem.set('');
    this.jwk.set('');
    this.jwks.set('');
    this.remoteJwks.set(null);
    this.remoteInfo.set(null);
    this.result.set(null);
    this.note.set(null);
    this.toast.info('Keys cleared from memory');
  }

  private keyMaterial(): KeyMaterial | null {
    switch (this.tab()) {
      case 'secret':
        return this.secret()
          ? { type: 'secret', value: this.secret(), encoding: this.encoding() }
          : null;
      case 'pem':
        return this.pem().trim() ? { type: 'pem', value: this.pem() } : null;
      case 'jwk':
        return this.jwk().trim() ? { type: 'jwk', value: this.jwk() } : null;
      case 'jwks':
        return this.jwks().trim() ? { type: 'jwks', value: this.jwks() } : null;
      case 'remote': {
        const json = this.remoteJwks();
        return json ? { type: 'jwks', value: json, source: this.remoteUrl() } : null;
      }
    }
  }

  private applyKey(key: KeyMaterial): void {
    switch (key.type) {
      case 'secret':
        this.tab.set('secret');
        this.secret.set(key.value);
        this.encoding.set(key.encoding);
        break;
      case 'pem':
        this.tab.set('pem');
        this.pem.set(key.value);
        break;
      case 'jwk':
        this.tab.set('jwk');
        this.jwk.set(key.value);
        break;
      case 'jwks':
        this.tab.set('jwks');
        this.jwks.set(key.value);
        break;
    }
  }
}
