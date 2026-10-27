import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { configureClock } from '../../testing/test-tokens';
import { routes } from '../app.routes';
import { DemoTokenService } from '../core/services/demo-token.service';
import { WorkspaceService } from '../core/services/workspace.service';

async function waitFor(
  harness: RouterTestingHarness,
  predicate: () => boolean,
  timeoutMs = 4000,
): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    harness.detectChanges();
    await harness.fixture.whenStable();
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error('Condition not met in time:\n' + text(harness).slice(0, 2000));
}

const text = (harness: RouterTestingHarness) =>
  (harness.routeNativeElement as HTMLElement).textContent ?? '';

function button(harness: RouterTestingHarness, label: string): HTMLButtonElement {
  const found = [...(harness.routeNativeElement as HTMLElement).querySelectorAll('button')].find(
    (b) => b.textContent?.includes(label),
  );
  if (!found) throw new Error(`Button "${label}" not found`);
  return found;
}

describe('Feature pages (routed smoke tests)', () => {
  let harness: RouterTestingHarness;
  let workspace: WorkspaceService;
  let demos: DemoTokenService;

  beforeEach(async () => {
    configureClock(Date.now());
    TestBed.configureTestingModule({ providers: [provideRouter(routes)] });
    harness = await RouterTestingHarness.create();
    workspace = TestBed.inject(WorkspaceService);
    demos = TestBed.inject(DemoTokenService);
  });

  it.each([
    ['/', 'Diagnose JWT Authentication & Authorization Issues'],
    ['/troubleshooter', 'Ready to investigate'],
    ['/inspector', 'Paste a JWT to start'],
    ['/security', 'Analyze a token'],
    ['/timeline', 'No token loaded'],
    ['/compare', 'Two decodable tokens are needed'],
    ['/permissions', 'Explore token permissions'],
    ['/generator', 'Payload preview'],
    ['/signature', 'Not Verified'],
    ['/demos', 'HTTP 403: Missing Role'],
  ])('renders %s', async (url, expected) => {
    await harness.navigateByUrl(url);
    harness.detectChanges();
    expect(text(harness)).toContain(expected);
  });

  it('renders every token tool with a loaded token', async () => {
    workspace.setToken((await demos.scenario('valid')).token);
    const expectations: [string, string][] = [
      ['/inspector', 'Claim details'],
      ['/timeline', 'Within Validity Window'],
      ['/security', 'Security Score'],
      ['/permissions', 'Permission Matrix'],
      ['/signature', 'Verify Signature'],
    ];
    for (const [url, expected] of expectations) {
      await harness.navigateByUrl(url);
      harness.detectChanges();
      expect(text(harness)).toContain(expected);
    }
  });

  it('Troubleshooter runs the Demo 3 pipeline from the Demo Playground', async () => {
    await harness.navigateByUrl('/demos');
    harness.detectChanges();
    button(harness, 'Run diagnosis').click();
    await waitFor(harness, () => text(harness).includes('Diagnostic pipeline'));
    expect(text(harness)).toContain('Access Denied — Simulated');
    const page = text(harness);
    expect(page).toContain('Most Likely Cause: Missing Required Authority');
    expect(page).toContain('Final Diagnosis');
    expect(page).toContain('Spring Security Analyzer');
    expect(page).toContain('Copy Diagnosis Report');
  });

  it('Troubleshooter applies the suggested Spring mapping fix (Demo 7)', async () => {
    const scenario = await demos.scenario('spring-mapping');
    workspace.troubleshooterPreset.set(scenario.preset!);
    await harness.navigateByUrl('/troubleshooter');
    await waitFor(harness, () => text(harness).includes('Permission Claim Not Mapped'));
    button(harness, 'Apply fix').click();
    await waitFor(harness, () => text(harness).includes('Access Granted — Simulated'));
  });

  it('Signature Verifier reports the tampered demo token as invalid (Demo 5)', async () => {
    await harness.navigateByUrl('/demos');
    harness.detectChanges();
    button(harness, 'Verify signature').click();
    await waitFor(harness, () =>
      text(harness).includes('The signature does not match the provided key'),
    );
  });

  it('JWT Compare opens the comparison demo (Demo 6)', async () => {
    await harness.navigateByUrl('/demos');
    harness.detectChanges();
    button(harness, 'Open comparison').click();
    await waitFor(harness, () => text(harness).includes('JSON side by side'));
    expect(text(harness)).toContain('removed');
  });

  it('JWT Generator signs an HS256 token and sends it to the Troubleshooter', async () => {
    await harness.navigateByUrl('/generator');
    harness.detectChanges();
    button(harness, 'Generate signed token').click();
    await waitFor(harness, () => text(harness).includes('Generated token'));
    button(harness, 'Diagnose Generated Token').click();
    await waitFor(harness, () =>
      text(harness).includes('Signature verified with the provided key'),
    );
  });

  it('Dashboard demo button opens the Troubleshooter scenario', async () => {
    await harness.navigateByUrl('/');
    harness.detectChanges();
    button(harness, 'Try Authentication Demo').click();
    await waitFor(harness, () => text(harness).includes('Diagnostic pipeline'));
    expect(text(harness)).toContain('Access Denied — Simulated');
  });
});
