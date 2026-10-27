export type JsonObject = Record<string, unknown>;

export function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface PathMatch {
  path: string;
  value: unknown;
}

/**
 * Resolves a dot-separated path against an object. Supports `*` as a wildcard
 * for object keys, e.g. `resource_access.*.roles`.
 */
export function resolvePath(source: unknown, path: string): PathMatch[] {
  const parts = path
    .split('.')
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    return [];
  }
  let current: PathMatch[] = [{ path: '', value: source }];
  for (const part of parts) {
    const next: PathMatch[] = [];
    for (const match of current) {
      if (!isPlainObject(match.value)) {
        continue;
      }
      if (part === '*') {
        for (const [key, value] of Object.entries(match.value)) {
          next.push({ path: join(match.path, key), value });
        }
      } else if (Object.prototype.hasOwnProperty.call(match.value, part)) {
        next.push({ path: join(match.path, part), value: match.value[part] });
      }
    }
    current = next;
  }
  return current;
}

function join(base: string, key: string): string {
  return base ? `${base}.${key}` : key;
}

/** Splits a list typed by the user ("a, b c") into trimmed non-empty values. */
export function splitList(value: string | null | undefined): string[] {
  if (!value) {
    return [];
  }
  return [
    ...new Set(
      value
        .split(/[,\s]+/)
        .map((v) => v.trim().replace(/^["']|["']$/g, ''))
        .filter(Boolean),
    ),
  ];
}

export function safeStringify(value: unknown, space = 2): string {
  try {
    return JSON.stringify(value, null, space) ?? String(value);
  } catch {
    return String(value);
  }
}
