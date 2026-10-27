import { TestBed } from '@angular/core/testing';
import { ClockService, FixedClock } from '../app/core/services/clock.service';
import { stringToBase64Url } from '../app/core/utils/base64url';

/** 2026-01-15T12:00:00Z — fixed instant used by temporal tests. */
export const NOW_MS = Date.UTC(2026, 0, 15, 12, 0, 0);
export const NOW = NOW_MS / 1000;

/** Builds an unsigned-but-well-formed compact token (fake signature) for logic tests. */
export function fakeToken(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' },
  signature = 'c2lnbmF0dXJl',
): string {
  return `${stringToBase64Url(JSON.stringify(header))}.${stringToBase64Url(JSON.stringify(payload))}.${signature}`;
}

export function configureClock(instant = NOW_MS): FixedClock {
  const clock = new FixedClock(instant);
  TestBed.configureTestingModule({ providers: [{ provide: ClockService, useValue: clock }] });
  return clock;
}
