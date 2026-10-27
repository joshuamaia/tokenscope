import { TestBed } from '@angular/core/testing';
import { configureClock } from '../../../testing/test-tokens';
import { SignatureResult } from '../models/signature.models';
import { DEMO_SECRET, DemoTokenService } from './demo-token.service';
import { JwtDecoderService } from './jwt-decoder.service';
import { JwtSignatureService } from './jwt-signature.service';
import { JwtTimelineService } from './jwt-timeline.service';
import {
  DEFAULT_TROUBLESHOOTER_INPUT,
  JwtTroubleshooterService,
} from './jwt-troubleshooter.service';
import { ClockService } from './clock.service';

/** Runs every demo end to end, exactly as the Demo Playground does. */
describe('Demo scenarios (end to end)', () => {
  let demos: DemoTokenService;
  let troubleshooter: JwtTroubleshooterService;
  let signature: JwtSignatureService;

  beforeEach(() => {
    configureClock();
    demos = TestBed.inject(DemoTokenService);
    troubleshooter = TestBed.inject(JwtTroubleshooterService);
    signature = TestBed.inject(JwtSignatureService);
  });

  async function diagnoseDemo(id: Parameters<DemoTokenService['scenario']>[0]) {
    const scenario = await demos.scenario(id);
    const preset = scenario.preset!;
    const input = { ...DEFAULT_TROUBLESHOOTER_INPUT, ...preset.input };
    const sig: SignatureResult | null = preset.verificationKey
      ? await signature.verify(input.token, preset.verificationKey)
      : null;
    return troubleshooter.diagnose(input, sig);
  }

  it('Demo 1 — valid token is signed, decodable and within its validity window', async () => {
    const { token } = await demos.scenario('valid');
    const decoded = TestBed.inject(JwtDecoderService).decode(token);
    expect(decoded.valid).toBe(true);
    const now = TestBed.inject(ClockService).now();
    expect(TestBed.inject(JwtTimelineService).compute(decoded.payload, now).state).toBe('valid');
    expect(
      (await signature.verify(token, { type: 'secret', value: DEMO_SECRET, encoding: 'utf8' }))
        .status,
    ).toBe('verified');
  });

  it('Demo 2 — expired token → 401 JWT Expired with verified signature', async () => {
    const result = await diagnoseDemo('expired');
    expect(result.steps.find((s) => s.id === 'signature')?.status).toBe('passed');
    expect(result.mostLikely?.id).toBe('token-expired');
    expect(result.outcome).toBe('authentication-failure');
  });

  it('Demo 3 — HTTP 403 missing role → Access Denied — Simulated', async () => {
    const result = await diagnoseDemo('missing-role');
    expect(result.mostLikely?.id).toBe('missing-role');
    expect(result.mostLikely?.reason).toBe(
      'Token contains ROLE_USER, but the simulated endpoint rule requires ROLE_ADMIN.',
    );
    expect(result.headline.simulatedDecision).toBe('Access Denied — Simulated');
    expect(result.counts.failed).toBe(1);
    for (const id of [
      'structure',
      'decoding',
      'signature',
      'temporal',
      'issuer',
      'audience',
      'claims',
      'mapping',
    ]) {
      expect(result.steps.find((s) => s.id === id)?.status).toBe('passed');
    }
  });

  it('Demo 4 — HTTP 403 missing scope → Insufficient Scope', async () => {
    const result = await diagnoseDemo('missing-scope');
    expect(result.mostLikely?.id).toBe('missing-scope');
    expect(result.evaluation?.expression).toBe("hasAuthority('SCOPE_profile.write')");
  });

  it('Demo 5 — tampered token → Invalid Signature with the demo key', async () => {
    const scenario = await demos.scenario('invalid-signature');
    expect(
      (
        await signature.verify(scenario.token, {
          type: 'secret',
          value: DEMO_SECRET,
          encoding: 'utf8',
        })
      ).status,
    ).toBe('invalid');
    const result = await diagnoseDemo('invalid-signature');
    expect(result.mostLikely?.id).toBe('invalid-signature');
  });

  it('Demo 6 — comparison tokens differ in roles, scopes, issuer and expiration', async () => {
    const scenario = await demos.scenario('compare');
    expect(scenario.tokenB).toBeTruthy();
    expect(scenario.token).not.toBe(scenario.tokenB);
  });

  it('Demo 7 — Spring mapping: hasRole fails until roles are mapped, then passes', async () => {
    const result = await diagnoseDemo('spring-mapping');
    expect(result.mostLikely?.id).toBe('claim-not-mapped');
    const scenario = await demos.scenario('spring-mapping');
    const fixed = troubleshooter.diagnose(
      {
        ...DEFAULT_TROUBLESHOOTER_INPUT,
        ...scenario.preset!.input,
        mappingRules: result.suggestedMapping!,
      },
      null,
    );
    expect(fixed.evaluation?.granted).toBe(true);
  });
});
