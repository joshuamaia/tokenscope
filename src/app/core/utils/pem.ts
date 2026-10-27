import { base64ToBytes, bytesToBase64 } from './base64url';

export type PemLabel =
  | 'PUBLIC KEY'
  | 'RSA PUBLIC KEY'
  | 'CERTIFICATE'
  | 'PRIVATE KEY'
  | 'RSA PRIVATE KEY'
  | 'EC PRIVATE KEY'
  | string;

export interface PemBlock {
  label: PemLabel;
  der: Uint8Array;
}

const PEM_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

export function parsePem(input: string): PemBlock {
  const match = PEM_PATTERN.exec(input.trim());
  if (!match) {
    throw new Error(
      'No PEM block found. Expected "-----BEGIN PUBLIC KEY-----" … "-----END PUBLIC KEY-----".',
    );
  }
  const [, label, body] = match;
  try {
    return { label, der: base64ToBytes(body.replace(/\s+/g, '')) };
  } catch {
    throw new Error(`The PEM block "${label}" contains invalid Base64 content.`);
  }
}

export function toPem(der: Uint8Array, label: PemLabel): string {
  const base64 = bytesToBase64(der);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

interface DerNode {
  tag: number;
  start: number; // start of TLV
  valueStart: number;
  end: number; // exclusive
}

function readNode(bytes: Uint8Array, offset: number): DerNode {
  if (offset + 2 > bytes.length) throw new Error('Truncated DER structure');
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('Unsupported DER length encoding');
    length = 0;
    for (let i = 0; i < count; i++) {
      length = (length << 8) | bytes[offset + 2 + i];
    }
    header += count;
  }
  const end = offset + header + length;
  if (end > bytes.length) throw new Error('Truncated DER structure');
  return { tag, start: offset, valueStart: offset + header, end };
}

function children(bytes: Uint8Array, node: DerNode): DerNode[] {
  const result: DerNode[] = [];
  let offset = node.valueStart;
  while (offset < node.end) {
    const child = readNode(bytes, offset);
    result.push(child);
    offset = child.end;
  }
  return result;
}

/** Extracts the SubjectPublicKeyInfo from an X.509 certificate (DER). */
export function extractSpkiFromCertificate(der: Uint8Array): Uint8Array {
  const cert = readNode(der, 0);
  const [tbs] = children(der, cert);
  if (!tbs || tbs.tag !== 0x30) throw new Error('Invalid X.509 certificate structure');
  const fields = children(der, tbs);
  const index = fields[0]?.tag === 0xa0 ? 6 : 5; // optional explicit version [0]
  const spki = fields[index];
  if (!spki || spki.tag !== 0x30)
    throw new Error('Could not locate the public key in the certificate');
  return der.slice(spki.start, spki.end);
}

function encodeLength(length: number): number[] {
  if (length < 0x80) return [length];
  const bytes: number[] = [];
  while (length > 0) {
    bytes.unshift(length & 0xff);
    length >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

const RSA_ALGORITHM_IDENTIFIER = [
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/** Wraps a PKCS#1 RSAPublicKey into a SubjectPublicKeyInfo structure accepted by Web Crypto. */
export function wrapPkcs1RsaPublicKey(pkcs1: Uint8Array): Uint8Array {
  const bitString = [0x03, ...encodeLength(pkcs1.length + 1), 0x00, ...pkcs1];
  const body = [...RSA_ALGORITHM_IDENTIFIER, ...bitString];
  return new Uint8Array([0x30, ...encodeLength(body.length), ...body]);
}
