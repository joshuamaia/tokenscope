const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

export function isBase64Url(value: string): boolean {
  return BASE64URL_PATTERN.test(value) && value.length % 4 !== 1;
}

/** Decodes a Base64URL string (no padding) into bytes. Throws on invalid input. */
export function base64UrlToBytes(value: string): Uint8Array {
  if (!isBase64Url(value)) {
    throw new Error('Invalid Base64URL encoding');
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return base64ToBytes(padded);
}

export function base64ToBytes(value: string): Uint8Array {
  const clean = value.replace(/\s+/g, '');
  if (!BASE64_PATTERN.test(clean) || clean.length % 4 === 1) {
    throw new Error('Invalid Base64 encoding');
  }
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes Base64URL into a UTF-8 string. Throws if the bytes are not valid UTF-8. */
export function base64UrlToString(value: string): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(base64UrlToBytes(value));
}

export function stringToBase64Url(value: string): string {
  return bytesToBase64Url(utf8(value));
}

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>;
}

/** Copies bytes into a fresh ArrayBuffer-backed view (Web Crypto rejects views on foreign realms/buffers). */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
