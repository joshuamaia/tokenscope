import { Injectable } from '@angular/core';
import { JwtPayload } from '../models/jwt.models';
import { TemporalState, TimelineMarker, TimelineResult } from '../models/timeline.models';
import { isNumericDate } from './jwt-claims.service';

/**
 * Temporal validation (exp / nbf / iat). This says nothing about the
 * cryptographic validity of the token.
 */
@Injectable({ providedIn: 'root' })
export class JwtTimelineService {
  compute(payload: JwtPayload | null, nowMs: number, skewSeconds = 0): TimelineResult {
    const issues: string[] = [];
    const read = (claim: 'iat' | 'nbf' | 'exp'): number | null => {
      if (!payload || !(claim in payload)) return null;
      const value = payload[claim];
      if (!isNumericDate(value)) {
        issues.push(
          `"${claim}" is present but is not a valid NumericDate (got ${JSON.stringify(value)}).`,
        );
        return null;
      }
      return value * 1000;
    };
    const iat = read('iat');
    const nbf = read('nbf');
    const exp = read('exp');
    const skew = Math.max(0, skewSeconds) * 1000;

    if (iat !== null && exp !== null && iat > exp)
      issues.push('"iat" is later than "exp": the token expired before it was issued.');
    if (nbf !== null && exp !== null && nbf > exp)
      issues.push('"nbf" is later than "exp": the validity window is empty.');
    if (iat !== null && iat - skew > nowMs)
      issues.push(
        '"iat" is in the future — the issuer clock may be ahead or the token was crafted.',
      );

    const structural = issues.filter((i) => !i.includes('in the future'));
    let state: TemporalState;
    if (structural.length > 0) {
      state = 'invalid';
    } else if (nbf !== null && nowMs + skew < nbf) {
      state = 'not-yet-valid';
    } else if (exp === null) {
      state = 'missing-exp';
    } else if (nowMs - skew >= exp) {
      state = 'expired';
    } else {
      state = 'valid';
    }

    const start = nbf ?? iat;
    const totalSeconds = start !== null && exp !== null ? (exp - start) / 1000 : null;
    const elapsedSeconds = start !== null ? (nowMs - start) / 1000 : null;
    const remainingSeconds = exp !== null ? (exp - nowMs) / 1000 : null;
    const progress =
      totalSeconds !== null && totalSeconds > 0 && elapsedSeconds !== null
        ? Math.min(1, Math.max(0, elapsedSeconds / totalSeconds))
        : null;

    return {
      state,
      now: nowMs,
      iat,
      nbf,
      exp,
      start,
      totalSeconds,
      elapsedSeconds,
      remainingSeconds,
      progress,
      markers: this.markers(iat, nbf, exp, nowMs),
      issues,
      skewSeconds: Math.max(0, skewSeconds),
    };
  }

  private markers(
    iat: number | null,
    nbf: number | null,
    exp: number | null,
    now: number,
  ): TimelineMarker[] {
    const points: Omit<TimelineMarker, 'position'>[] = [];
    if (iat !== null) points.push({ key: 'iat', label: 'Issued At', time: iat });
    if (nbf !== null) points.push({ key: 'nbf', label: 'Not Before', time: nbf });
    points.push({ key: 'now', label: 'Now', time: now });
    if (exp !== null) points.push({ key: 'exp', label: 'Expiration', time: exp });
    const min = Math.min(...points.map((p) => p.time));
    const max = Math.max(...points.map((p) => p.time));
    const range = max - min || 1;
    return points.map((p) => ({
      ...p,
      position: points.length === 1 ? 50 : ((p.time - min) / range) * 100,
    }));
  }
}
