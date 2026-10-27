export type TemporalState = 'not-yet-valid' | 'valid' | 'expired' | 'missing-exp' | 'invalid';

export const TEMPORAL_STATE_LABEL: Record<TemporalState, string> = {
  'not-yet-valid': 'Not Yet Valid',
  valid: 'Within Validity Window',
  expired: 'Expired',
  'missing-exp': 'Missing Expiration',
  invalid: 'Invalid Temporal Claims',
};

export interface TimelineMarker {
  key: 'iat' | 'nbf' | 'now' | 'exp';
  label: string;
  time: number; // epoch ms
  position: number; // 0..100
}

export interface TimelineResult {
  state: TemporalState;
  now: number;
  iat: number | null;
  nbf: number | null;
  exp: number | null;
  /** Effective validity start (nbf, else iat). */
  start: number | null;
  totalSeconds: number | null;
  elapsedSeconds: number | null;
  remainingSeconds: number | null;
  progress: number | null; // 0..1
  markers: TimelineMarker[];
  issues: string[];
  skewSeconds: number;
}
