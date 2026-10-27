import { TestBed } from '@angular/core/testing';
import { NOW, NOW_MS } from '../../../testing/test-tokens';
import { JwtTimelineService } from './jwt-timeline.service';

describe('JwtTimelineService', () => {
  let timeline: JwtTimelineService;

  beforeEach(() => {
    timeline = TestBed.inject(JwtTimelineService);
  });

  it('is within the validity window and computes durations', () => {
    const r = timeline.compute({ iat: NOW - 600, exp: NOW + 1200 }, NOW_MS);
    expect(r.state).toBe('valid');
    expect(r.totalSeconds).toBe(1800);
    expect(r.elapsedSeconds).toBe(600);
    expect(r.remainingSeconds).toBe(1200);
    expect(r.progress).toBeCloseTo(1 / 3);
    expect(r.markers.map((m) => m.key)).toEqual(['iat', 'now', 'exp']);
  });

  it('detects expiration exactly at exp and honors clock skew', () => {
    expect(timeline.compute({ exp: NOW }, NOW_MS).state).toBe('expired');
    expect(timeline.compute({ exp: NOW - 30 }, NOW_MS, 60).state).toBe('valid');
    expect(timeline.compute({ exp: NOW - 61 }, NOW_MS, 60).state).toBe('expired');
  });

  it('detects not-yet-valid tokens', () => {
    expect(timeline.compute({ nbf: NOW + 300, exp: NOW + 900 }, NOW_MS).state).toBe(
      'not-yet-valid',
    );
    expect(timeline.compute({ nbf: NOW + 30, exp: NOW + 900 }, NOW_MS, 60).state).toBe('valid');
  });

  it('reports missing expiration', () => {
    expect(timeline.compute({ iat: NOW }, NOW_MS).state).toBe('missing-exp');
  });

  it('reports invalid temporal claims', () => {
    expect(timeline.compute({ iat: NOW + 100, exp: NOW }, NOW_MS).state).toBe('invalid');
    expect(timeline.compute({ nbf: NOW + 100, exp: NOW + 50 }, NOW_MS).state).toBe('invalid');
    expect(timeline.compute({ exp: 'tomorrow' }, NOW_MS).state).toBe('invalid');
  });

  it('flags iat in the future without invalidating the window', () => {
    const r = timeline.compute({ iat: NOW + 3600, exp: NOW + 7200 }, NOW_MS);
    expect(r.issues.some((i) => i.includes('future'))).toBe(true);
  });
});
