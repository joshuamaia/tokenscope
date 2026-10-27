import { isPlainObject } from './json-path';

export type DiffKind = 'added' | 'removed' | 'modified' | 'unchanged';

export interface DiffEntry {
  path: string;
  kind: DiffKind;
  before?: unknown;
  after?: unknown;
}

const MAX_DEPTH = 32;

/**
 * Deep structural diff of two JSON values. Objects are compared key by key;
 * arrays of primitives are compared as sets of values (order-insensitive, which
 * matches how roles/scopes are usually interpreted) and arrays of objects by index.
 */
export function deepDiff(before: unknown, after: unknown, path = '', depth = 0): DiffEntry[] {
  if (depth > MAX_DEPTH) {
    return [{ path, kind: deepEqual(before, after) ? 'unchanged' : 'modified', before, after }];
  }
  if (isPlainObject(before) && isPlainObject(after)) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    return keys.flatMap((key) => {
      const childPath = path ? `${path}.${key}` : key;
      const inBefore = Object.prototype.hasOwnProperty.call(before, key);
      const inAfter = Object.prototype.hasOwnProperty.call(after, key);
      if (inBefore && !inAfter)
        return [{ path: childPath, kind: 'removed' as const, before: before[key] }];
      if (!inBefore && inAfter)
        return [{ path: childPath, kind: 'added' as const, after: after[key] }];
      return deepDiff(before[key], after[key], childPath, depth + 1);
    });
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    const primitive = (v: unknown) => v === null || typeof v !== 'object';
    if (before.every(primitive) && after.every(primitive)) {
      if (deepEqual([...before].sort(), [...after].sort())) {
        return [{ path, kind: 'unchanged', before, after }];
      }
      return [{ path, kind: 'modified', before, after }];
    }
    const length = Math.max(before.length, after.length);
    const entries: DiffEntry[] = [];
    for (let i = 0; i < length; i++) {
      const childPath = `${path}[${i}]`;
      if (i >= before.length) entries.push({ path: childPath, kind: 'added', after: after[i] });
      else if (i >= after.length)
        entries.push({ path: childPath, kind: 'removed', before: before[i] });
      else entries.push(...deepDiff(before[i], after[i], childPath, depth + 1));
    }
    return entries;
  }
  return [{ path, kind: deepEqual(before, after) ? 'unchanged' : 'modified', before, after }];
}

export function deepEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (a === b) return true;
  if (depth > MAX_DEPTH) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => deepEqual(v, b[i], depth + 1));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    return (
      ka.length === kb.length &&
      ka.every(
        (k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k], depth + 1),
      )
    );
  }
  return Number.isNaN(a) && Number.isNaN(b);
}
