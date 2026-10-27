import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  AbstractControl,
  NonNullableFormBuilder,
  ReactiveFormsModule,
  ValidationErrors,
  Validators,
} from '@angular/forms';
import { Router } from '@angular/router';
import { map } from 'rxjs';
import { JwtPayload } from '../../core/models/jwt.models';
import { KeyMaterial, SecretEncoding } from '../../core/models/signature.models';
import { ClockService } from '../../core/services/clock.service';
import { SPRING_DEFAULT_MAPPING, ROLES_MAPPING } from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import {
  GeneratorAlg,
  JwtGeneratorService,
  RsaAlg,
  RsaKeyPair,
  SigningKey,
} from '../../core/services/jwt-generator.service';
import { ToastService } from '../../core/services/toast.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { isPlainObject, splitList } from '../../core/utils/json-path';
import { CopyButtonComponent } from '../../shared/components/copy-button/copy-button.component';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { JsonViewerComponent } from '../../shared/components/json-viewer/json-viewer.component';
import { TooltipDirective } from '../../shared/directives/tooltip.directive';

type ExpirationPreset = '5' | '15' | '30' | '60' | '1440' | 'custom';

const EXPIRATIONS: { value: ExpirationPreset; label: string }[] = [
  { value: '5', label: '5 min' },
  { value: '15', label: '15 min' },
  { value: '30', label: '30 min' },
  { value: '60', label: '1 hour' },
  { value: '1440', label: '24 hours' },
  { value: 'custom', label: 'Custom' },
];

const RESERVED = ['sub', 'iss', 'aud', 'iat', 'nbf', 'exp', 'roles', 'scope', 'jti'];

function jsonObjectValidator(control: AbstractControl<string>): ValidationErrors | null {
  const value = control.value?.trim();
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return isPlainObject(parsed) ? null : { json: 'Custom claims must be a JSON object.' };
  } catch (e) {
    return { json: `Invalid JSON: ${(e as Error).message}` };
  }
}

@Component({
  selector: 'ts-jwt-generator',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    ReactiveFormsModule,
    IconComponent,
    CopyButtonComponent,
    JsonViewerComponent,
    TooltipDirective,
  ],
  templateUrl: './jwt-generator.component.html',
  styleUrl: './jwt-generator.component.scss',
})
export class JwtGeneratorComponent {
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly generator = inject(JwtGeneratorService);
  private readonly decoder = inject(JwtDecoderService);
  private readonly clock = inject(ClockService);
  private readonly router = inject(Router);
  private readonly toast = inject(ToastService);
  private readonly workspace = inject(WorkspaceService);

  protected readonly expirations = EXPIRATIONS;
  protected readonly algorithms: GeneratorAlg[] = [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
  ];

  protected readonly form = this.fb.group({
    alg: this.fb.control<GeneratorAlg>('HS256'),
    sub: ['user-1024', [Validators.maxLength(256)]],
    iss: ['https://auth.example.com', [Validators.maxLength(512)]],
    aud: ['orders-api', [Validators.maxLength(512)]],
    roles: ['USER', [Validators.maxLength(512)]],
    scopes: ['openid profile.read', [Validators.maxLength(1024)]],
    includeIat: [true],
    includeNbf: [false],
    nbfOffsetMinutes: [0, [Validators.min(-525600), Validators.max(525600)]],
    includeJti: [true],
    expiration: this.fb.control<ExpirationPreset>('15'),
    customMinutes: [90, [Validators.min(-525600), Validators.max(5256000)]],
    kid: ['', [Validators.maxLength(128)]],
    customClaims: [
      '{\n  "department": "engineering"\n}',
      [jsonObjectValidator, Validators.maxLength(16000)],
    ],
    secret: [''],
    secretEncoding: this.fb.control<SecretEncoding>('base64url'),
  });

  protected readonly value = toSignal(
    this.form.valueChanges.pipe(map(() => this.form.getRawValue())),
    { initialValue: this.form.getRawValue() },
  );
  protected readonly isRsa = computed(() => this.value().alg.startsWith('RS'));
  protected readonly keyPair = signal<RsaKeyPair | null>(null);
  protected readonly generatingKey = signal(false);
  protected readonly signing = signal(false);
  protected readonly token = signal<string | null>(null);
  protected readonly signedWith = signal<KeyMaterial | null>(null);
  protected readonly showSecret = signal(false);

  protected readonly secretBits = computed(() => {
    const v = this.value();
    try {
      return this.generator.secretBytes(v.secret, v.secretEncoding).length * 8;
    } catch {
      return null;
    }
  });
  protected readonly minBits = computed(() => Number(this.value().alg.slice(2)));
  protected readonly preview = computed(() =>
    this.buildPayload(this.value(), Math.floor(this.clock.tick() / 1000), true),
  );
  protected readonly decoded = computed(() => {
    const token = this.token();
    return token ? this.decoder.decode(token) : null;
  });
  protected readonly publicJwkJson = computed(() => {
    const pair = this.keyPair();
    return pair ? JSON.stringify(pair.publicJwk, null, 2) : '';
  });
  protected readonly jwksJson = computed(() => {
    const pair = this.keyPair();
    return pair ? JSON.stringify({ keys: [pair.publicJwk] }, null, 2) : '';
  });

  generateSecret(): void {
    this.form.patchValue({
      secret: this.generator.generateSecret(Math.max(32, this.minBits() / 8)),
      secretEncoding: 'base64url',
    });
    this.showSecret.set(true);
    this.toast.success('Random test secret generated locally');
  }

  async generateKeyPair(): Promise<void> {
    this.generatingKey.set(true);
    try {
      this.keyPair.set(await this.generator.generateRsaKeyPair(this.value().alg as RsaAlg));
      this.toast.success('RSA-2048 key pair generated locally (private key is non-extractable)');
    } catch (e) {
      this.toast.error((e as Error).message);
    } finally {
      this.generatingKey.set(false);
    }
  }

  discardKeys(): void {
    this.keyPair.set(null);
    this.form.patchValue({ secret: '' });
    this.token.set(null);
    this.signedWith.set(null);
    this.toast.info('Keys discarded from memory');
  }

  async generate(): Promise<void> {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      this.toast.warning('Please fix the highlighted fields.');
      return;
    }
    const v = this.form.getRawValue();
    let key: SigningKey;
    let verification: KeyMaterial;
    if (this.isRsa()) {
      let pair = this.keyPair();
      if (!pair || pair.alg !== v.alg) {
        await this.generateKeyPair();
        pair = this.keyPair();
      }
      if (!pair) return;
      key = { alg: v.alg as RsaAlg, privateKey: pair.privateKey, kid: pair.kid };
      verification = { type: 'pem', value: pair.publicPem };
    } else {
      if (!v.secret) this.generateSecret();
      const secret = this.form.getRawValue().secret;
      const bits = this.secretBits();
      if (bits === null) {
        this.toast.error(`The secret is not valid ${v.secretEncoding}.`);
        return;
      }
      key = { alg: v.alg as 'HS256' | 'HS384' | 'HS512', secret, encoding: v.secretEncoding };
      verification = { type: 'secret', value: secret, encoding: v.secretEncoding };
    }
    this.signing.set(true);
    try {
      const payload = this.buildPayload(v, Math.floor(this.clock.now() / 1000), false);
      const token = await this.generator.sign(
        payload,
        key,
        v.kid.trim() ? { kid: v.kid.trim() } : {},
      );
      this.token.set(token);
      this.signedWith.set(verification);
      this.toast.success(`Signed ${v.alg} token generated`);
    } catch (e) {
      this.toast.error(`Signing failed: ${(e as Error).message}`);
    } finally {
      this.signing.set(false);
    }
  }

  inspect(): void {
    this.sendTo('/inspector');
  }

  analyze(): void {
    this.sendTo('/security');
  }

  compare(): void {
    const token = this.token();
    if (!token) return;
    const previous = this.workspace.token();
    this.workspace.compareA.set(previous && previous !== token ? previous : '');
    this.workspace.compareB.set(token);
    this.sendTo('/compare', false);
  }

  diagnose(): void {
    const token = this.token();
    if (!token) return;
    const hasRoles = splitList(this.value().roles).length > 0;
    this.workspace.troubleshooterPreset.set({
      label: 'Generated token',
      autoRun: true,
      verificationKey: this.signedWith() ?? undefined,
      input: {
        token,
        httpStatus: 'unknown',
        expectedIssuer: this.value().iss.trim(),
        expectedAudience: splitList(this.value().aud).join(', '),
        signatureMode: 'verify-now',
        springMode: true,
        mappingRules: hasRoles
          ? [...SPRING_DEFAULT_MAPPING, ROLES_MAPPING]
          : [...SPRING_DEFAULT_MAPPING],
        requiredRoles: '',
        requiredScopes: '',
        requiredAuthorities: '',
        customExpression: '',
      },
    });
    this.sendTo('/troubleshooter');
  }

  verify(): void {
    const token = this.token();
    const key = this.signedWith();
    if (!token || !key) return;
    this.workspace.verifierPreset.set({
      token,
      key,
      autoRun: true,
      note: 'Verifying the generated token with the key that signed it.',
    });
    this.sendTo('/signature');
  }

  private sendTo(path: string, setActive = true): void {
    const token = this.token();
    if (!token) return;
    if (setActive) this.workspace.setToken(token);
    void this.router.navigateByUrl(path);
  }

  private buildPayload(
    v: ReturnType<typeof this.form.getRawValue>,
    now: number,
    preview: boolean,
  ): JwtPayload {
    const payload: JwtPayload = {};
    if (v.iss.trim()) payload['iss'] = v.iss.trim();
    if (v.sub.trim()) payload['sub'] = v.sub.trim();
    const aud = splitList(v.aud);
    if (aud.length) payload['aud'] = aud.length === 1 ? aud[0] : aud;
    if (v.includeIat) payload['iat'] = now;
    if (v.includeNbf) payload['nbf'] = now + Math.round(Number(v.nbfOffsetMinutes) || 0) * 60;
    const minutes = v.expiration === 'custom' ? Number(v.customMinutes) || 0 : Number(v.expiration);
    payload['exp'] = now + Math.round(minutes * 60);
    const roles = splitList(v.roles);
    if (roles.length) payload['roles'] = roles;
    const scopes = v.scopes.split(/\s+/).filter(Boolean);
    if (scopes.length) payload['scope'] = scopes.join(' ');
    if (v.includeJti) payload['jti'] = preview ? '<random on generate>' : this.generator.randomId();
    try {
      const custom: unknown = v.customClaims.trim() ? JSON.parse(v.customClaims) : {};
      if (isPlainObject(custom)) {
        for (const [k, val] of Object.entries(custom)) {
          if (!RESERVED.includes(k)) payload[k] = val;
        }
      }
    } catch {
      // validator reports the error
    }
    return payload;
  }
}
