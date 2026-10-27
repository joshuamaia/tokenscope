export type TimeZoneMode = 'local' | 'utc' | 'America/Sao_Paulo';

export const TIME_ZONE_OPTIONS: { value: TimeZoneMode; label: string }[] = [
  { value: 'local', label: 'Local time' },
  { value: 'utc', label: 'UTC' },
  { value: 'America/Sao_Paulo', label: 'America/Sao_Paulo' },
];

function resolveZone(mode: TimeZoneMode): string | undefined {
  if (mode === 'local') {
    return undefined;
  }
  return mode === 'utc' ? 'UTC' : mode;
}

export function formatDateTime(epochMs: number, mode: TimeZoneMode = 'local'): string {
  if (!Number.isFinite(epochMs)) {
    return 'Invalid date';
  }
  const date = new Date(epochMs);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid date';
  }
  const formatted = new Intl.DateTimeFormat('en-US', {
    timeZone: resolveZone(mode),
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZoneName: 'short',
  }).format(date);
  return formatted;
}

export function formatTime(epochMs: number, mode: TimeZoneMode = 'local'): string {
  if (!Number.isFinite(epochMs)) {
    return '—';
  }
  return new Intl.DateTimeFormat('en-US', {
    timeZone: resolveZone(mode),
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(new Date(epochMs));
}

/** Formats seconds as a compact human duration: "1d 2h", "14m 5s", "45s". */
export function formatDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds)) {
    return '—';
  }
  const negative = totalSeconds < 0;
  let s = Math.floor(Math.abs(totalSeconds));
  const days = Math.floor(s / 86400);
  s -= days * 86400;
  const hours = Math.floor(s / 3600);
  s -= hours * 3600;
  const minutes = Math.floor(s / 60);
  s -= minutes * 60;
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes && parts.length < 2) parts.push(`${minutes}m`);
  if ((s || parts.length === 0) && parts.length < 2) parts.push(`${s}s`);
  return (negative ? '-' : '') + parts.join(' ');
}

/** Countdown format HH:MM:SS (days prefixed when needed). */
export function formatCountdown(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${days ? days + 'd ' : ''}${pad(h)}:${pad(m)}:${pad(sec)}`;
}

export function toIso(epochMs: number): string {
  try {
    return new Date(epochMs).toISOString();
  } catch {
    return 'Invalid date';
  }
}
