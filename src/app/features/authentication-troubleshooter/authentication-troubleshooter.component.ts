import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  OnInit,
  computed,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import {
  FormArray,
  FormControl,
  FormGroup,
  NonNullableFormBuilder,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms';
import { map } from 'rxjs';
import {
  DiagnosisResult,
  HTTP_METHODS,
  HttpMethod,
  HttpStatusInput,
  SignatureMode,
  StepId,
  TroubleshooterInput,
  TroubleshooterPreset,
} from '../../core/models/diagnosis.models';
import {
  AuthorityMappingRule,
  RULE_TYPE_OPTIONS,
  RuleType,
} from '../../core/models/permission.models';
import { KeyMaterial, SecretEncoding, SignatureResult } from '../../core/models/signature.models';
import {
  DemoId,
  DemoTokenService,
  ROLES_MAPPING,
  SPRING_DEFAULT_MAPPING,
} from '../../core/services/demo-token.service';
import { JwtDecoderService } from '../../core/services/jwt-decoder.service';
import { JwtSignatureService } from '../../core/services/jwt-signature.service';
import {
  DEFAULT_TROUBLESHOOTER_INPUT,
  JwtTroubleshooterService,
} from '../../core/services/jwt-troubleshooter.service';
import { ToastService } from '../../core/services/toast.service';
import { WorkspaceService } from '../../core/services/workspace.service';
import { IconComponent } from '../../shared/components/icon/icon.component';
import { TokenInputComponent } from '../../shared/components/token-input/token-input.component';
import { TooltipDirective } from '../../shared/directives/tooltip.directive';
import { DiagnosisPipelineComponent } from './diagnosis-pipeline/diagnosis-pipeline.component';
import { DiagnosisReportComponent } from './diagnosis-report/diagnosis-report.component';
import { DiagnosisSummaryComponent } from './diagnosis-summary/diagnosis-summary.component';
import { SpringAnalyzerComponent } from './spring-analyzer/spring-analyzer.component';
import { STEP_ICON } from './status-visuals';

type KeyType = 'secret' | 'pem' | 'jwk' | 'jwks';
type MappingGroup = FormGroup<{
  claim: FormControl<string>;
  prefix: FormControl<string>;
  delimiter: FormControl<string>;
}>;

const MAPPING_PRESETS: { label: string; rule: AuthorityMappingRule }[] = [
  { label: 'scope/scp → SCOPE_ (default)', rule: SPRING_DEFAULT_MAPPING[0] },
  { label: 'roles → ROLE_', rule: ROLES_MAPPING },
  { label: 'authorities (no prefix)', rule: { claim: 'authorities', prefix: '', delimiter: ' ' } },
  {
    label: 'realm_access.roles → ROLE_ (Keycloak)',
    rule: { claim: 'realm_access.roles', prefix: 'ROLE_', delimiter: ' ' },
  },
  { label: 'groups → ROLE_', rule: { claim: 'groups', prefix: 'ROLE_', delimiter: ' ' } },
];

const PIPELINE_PREVIEW = [
  'Token Structure',
  'Token Decoding',
  'Signature Verification',
  'Temporal Validation',
  'Issuer Validation',
  'Audience Validation',
  'Claims Extraction',
  'Authority Mapping',
  'Permission Evaluation',
  'Final Diagnosis',
];

@Component({
  selector: 'ts-authentication-troubleshooter',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    ReactiveFormsModule,
    IconComponent,
    TokenInputComponent,
    TooltipDirective,
    DiagnosisPipelineComponent,
    DiagnosisSummaryComponent,
    SpringAnalyzerComponent,
    DiagnosisReportComponent,
  ],
  templateUrl: './authentication-troubleshooter.component.html',
  styleUrl: './authentication-troubleshooter.component.scss',
})
export class AuthenticationTroubleshooterComponent implements OnInit {
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly troubleshooter = inject(JwtTroubleshooterService);
  private readonly signatureService = inject(JwtSignatureService);
  private readonly decoder = inject(JwtDecoderService);
  private readonly demos = inject(DemoTokenService);
  private readonly toast = inject(ToastService);
  private readonly workspace = inject(WorkspaceService);
  private readonly results = viewChild<ElementRef<HTMLElement>>('results');

  protected readonly methods = HTTP_METHODS;
  protected readonly ruleTypes = RULE_TYPE_OPTIONS;
  protected readonly mappingPresets = MAPPING_PRESETS;
  protected readonly pipelinePreview = PIPELINE_PREVIEW;
  protected readonly stepIcon = STEP_ICON;
  protected readonly statusOptions: { value: HttpStatusInput; label: string }[] = [
    { value: '401', label: '401 Unauthorized' },
    { value: '403', label: '403 Forbidden' },
    { value: 'unknown', label: 'Unknown' },
  ];

  protected readonly form = this.fb.group({
    token: [''],
    httpStatus: this.fb.control<HttpStatusInput>('403'),
    method: this.fb.control<HttpMethod>('GET'),
    endpoint: ['/api/admin/users', [Validators.maxLength(512)]],
    expectedIssuer: ['', [Validators.maxLength(512)]],
    expectedAudience: ['', [Validators.maxLength(512)]],
    requiredRoles: ['', [Validators.maxLength(512)]],
    requiredScopes: ['', [Validators.maxLength(512)]],
    requiredAuthorities: ['', [Validators.maxLength(512)]],
    ruleType: this.fb.control<RuleType>('hasRole'),
    customExpression: ['', [Validators.maxLength(2000)]],
    clockSkewSeconds: [60, [Validators.required, Validators.min(0), Validators.max(3600)]],
    springMode: [true],
    signatureMode: this.fb.control<SignatureMode>('skip'),
    keyType: this.fb.control<KeyType>('secret'),
    keyValue: [''],
    secretEncoding: this.fb.control<SecretEncoding>('utf8'),
    mappingRules: this.fb.array<MappingGroup>(SPRING_DEFAULT_MAPPING.map((r) => this.ruleGroup(r))),
  });

  protected readonly value = toSignal(
    this.form.valueChanges.pipe(map(() => this.form.getRawValue())),
    {
      initialValue: this.form.getRawValue(),
    },
  );

  protected readonly result = signal<DiagnosisResult | null>(null);
  protected readonly running = signal(false);
  protected readonly presetLabel = signal<string | null>(null);
  protected readonly focusStep = signal<StepId | null>(null);
  protected readonly showKey = signal(false);

  protected readonly payload = computed(() => this.decoder.decode(this.value().token).payload);
  protected readonly input = computed<TroubleshooterInput>(() => this.toInput(this.value()));
  protected readonly expression = computed(() =>
    this.troubleshooter.requirementExpression(this.input()),
  );
  protected readonly builtExpression = computed(() =>
    this.troubleshooter.requirementExpression({ ...this.input(), customExpression: '' }),
  );
  protected readonly verifierResult = computed(() =>
    this.workspace.verificationFor(this.value().token),
  );
  protected readonly statusLabel = computed(
    () => this.statusOptions.find((s) => s.value === this.result()?.httpStatus)?.label ?? '',
  );

  get mappingRules(): FormArray<MappingGroup> {
    return this.form.controls.mappingRules;
  }

  ngOnInit(): void {
    const preset = this.workspace.consumeTroubleshooterPreset();
    if (preset) {
      this.applyPreset(preset);
    } else if (this.workspace.token()) {
      this.form.controls.token.setValue(this.workspace.token());
    }
  }

  async run(): Promise<void> {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      this.toast.warning('Please fix the highlighted fields.');
      return;
    }
    this.running.set(true);
    try {
      const input = this.input();
      const signature = await this.resolveSignature(input);
      const result = this.troubleshooter.diagnose(input, signature);
      this.result.set(result);
      this.focusStep.set(
        result.steps.find((s) => s.status === 'failed')?.id ??
          result.steps.find((s) => s.status === 'warning')?.id ??
          'final',
      );
      if (input.token.trim()) this.workspace.setToken(input.token);
      this.scrollToResults();
    } catch (e) {
      this.toast.error(`Diagnosis failed: ${(e as Error).message}`);
    } finally {
      this.running.set(false);
    }
  }

  async loadDemo(id: DemoId): Promise<void> {
    const scenario = await this.demos.scenario(id);
    if (scenario.preset) this.applyPreset(scenario.preset);
  }

  addRule(rule: AuthorityMappingRule = { claim: '', prefix: 'ROLE_', delimiter: ' ' }): void {
    this.mappingRules.push(this.ruleGroup(rule));
  }

  addPreset(index: string): void {
    const preset = MAPPING_PRESETS[Number(index)];
    if (preset) this.addRule(preset.rule);
  }

  removeRule(index: number): void {
    this.mappingRules.removeAt(index);
  }

  applyMapping(rules: AuthorityMappingRule[]): void {
    this.setRules(rules);
    this.toast.success('Authority mapping updated — re-running the diagnosis');
    void this.run();
  }

  useBuiltExpression(): void {
    this.form.controls.customExpression.setValue('');
  }

  reset(): void {
    this.applyValues(DEFAULT_TROUBLESHOOTER_INPUT);
    this.form.controls.keyValue.setValue('');
    this.result.set(null);
    this.presetLabel.set(null);
  }

  private async resolveSignature(input: TroubleshooterInput): Promise<SignatureResult | null> {
    if (input.signatureMode === 'use-verifier') return this.workspace.verificationFor(input.token);
    if (input.signatureMode !== 'verify-now') return null;
    const raw = this.form.getRawValue();
    if (!raw.keyValue.trim()) {
      this.toast.warning(
        'No verification key provided — signature will be reported as Not Verified.',
      );
      return null;
    }
    const key: KeyMaterial =
      raw.keyType === 'secret'
        ? { type: 'secret', value: raw.keyValue, encoding: raw.secretEncoding }
        : { type: raw.keyType, value: raw.keyValue };
    const result = await this.signatureService.verify(input.token, key);
    this.workspace.recordVerification(input.token, result);
    return result;
  }

  private applyPreset(preset: TroubleshooterPreset): void {
    this.applyValues({ ...DEFAULT_TROUBLESHOOTER_INPUT, ...preset.input });
    const key = preset.verificationKey;
    if (key) {
      this.form.patchValue({
        keyType: key.type,
        keyValue: key.value,
        ...(key.type === 'secret' ? { secretEncoding: key.encoding } : {}),
      });
    }
    this.presetLabel.set(preset.label ?? null);
    this.result.set(null);
    if (preset.autoRun) void this.run();
  }

  private applyValues(input: TroubleshooterInput): void {
    const { mappingRules, ...rest } = input;
    this.form.patchValue(rest);
    this.setRules(mappingRules);
  }

  private setRules(rules: AuthorityMappingRule[]): void {
    this.mappingRules.clear();
    rules.forEach((r) => this.mappingRules.push(this.ruleGroup(r)));
  }

  private ruleGroup(rule: AuthorityMappingRule): MappingGroup {
    return this.fb.group({
      claim: [rule.claim, [Validators.required, Validators.maxLength(200)]],
      prefix: [rule.prefix, [Validators.maxLength(50)]],
      delimiter: [rule.delimiter, [Validators.maxLength(5)]],
    });
  }

  private toInput(v: ReturnType<typeof this.form.getRawValue>): TroubleshooterInput {
    return {
      token: v.token,
      httpStatus: v.httpStatus,
      method: v.method,
      endpoint: v.endpoint.trim(),
      expectedIssuer: v.expectedIssuer,
      expectedAudience: v.expectedAudience,
      requiredRoles: v.requiredRoles,
      requiredScopes: v.requiredScopes,
      requiredAuthorities: v.requiredAuthorities,
      ruleType: v.ruleType,
      customExpression: v.customExpression,
      clockSkewSeconds: Number(v.clockSkewSeconds) || 0,
      springMode: v.springMode,
      mappingRules: v.mappingRules
        .filter((r) => r.claim.trim())
        .map((r) => ({ claim: r.claim.trim(), prefix: r.prefix, delimiter: r.delimiter || ' ' })),
      signatureMode: v.signatureMode,
    };
  }

  private scrollToResults(): void {
    if (typeof window === 'undefined' || window.innerWidth > 1180) return;
    setTimeout(
      () => this.results()?.nativeElement.scrollIntoView?.({ behavior: 'smooth', block: 'start' }),
      50,
    );
  }
}
