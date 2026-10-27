import { DestroyRef, Injectable, PLATFORM_ID, inject, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

/**
 * Single source of time for the whole app. Tests replace it with a fixed
 * clock so temporal rules are deterministic.
 */
@Injectable({ providedIn: 'root' })
export class ClockService {
  private readonly ticker = signal(Date.now());
  private intervalId: ReturnType<typeof setInterval> | null = null;

  constructor() {
    if (isPlatformBrowser(inject(PLATFORM_ID))) {
      this.intervalId = setInterval(() => this.ticker.set(this.now()), 1000);
      inject(DestroyRef).onDestroy(() => {
        if (this.intervalId) clearInterval(this.intervalId);
      });
    }
  }

  /** Current time in epoch milliseconds. */
  now(): number {
    return Date.now();
  }

  /** Signal updated every second in the browser — use it for live countdowns. */
  readonly tick = this.ticker.asReadonly();
}

/** Controllable clock for tests: `{ provide: ClockService, useValue: new FixedClock(t) }`. */
export class FixedClock implements Pick<ClockService, 'now' | 'tick'> {
  private readonly instant = signal(0);
  readonly tick = this.instant.asReadonly();

  constructor(instant: number) {
    this.instant.set(instant);
  }

  now(): number {
    return this.instant();
  }

  set(instant: number): void {
    this.instant.set(instant);
  }

  advance(seconds: number): void {
    this.instant.update((t) => t + seconds * 1000);
  }
}
