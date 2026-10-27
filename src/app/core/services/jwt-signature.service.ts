import { Injectable, inject } from '@angular/core';
import {
  JwksFetchResult,
  KeyMaterial,
  SignatureResult,
  SignatureStatus,
} from '../models/signature.models';
import { base64ToBytes, base64UrlToBytes, toArrayBuffer, utf8 } from '../utils/base64url';
import { isPlainObject } from '../utils/json-path';
import { extractSpkiFromCertificate, parsePem, wrapPkcs1RsaPublicKey } from '../utils/pem';
import { ClockService } from './clock.service';
import { JwtDecoderService } from './jwt-decoder.service';

type Family = 'HMAC' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'ECDSA' | 'Ed25519';

interface AlgSpec {
  family: Family;
  hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  saltLength?: number;
  curve?: 'P-256' | 'P-384' | 'P-521';
  signatureBytes?: number;
  minSecretBytes?: number;
  kty: 'oct' | 'RSA' | 'EC' | 'OKP';
  label: string;
}

export const ALGORITHMS: Record<string, AlgSpec> = {
  HS256: {
    family: 'HMAC',
    hash: 'SHA-256',
    minSecretBytes: 32,
    kty: 'oct',
    label: 'HMAC using SHA-256',
  },
  HS384: {
    family: 'HMAC',
    hash: 'SHA-384',
    minSecretBytes: 48,
    kty: 'oct',
    label: 'HMAC using SHA-384',
  },
  HS512: {
    family: 'HMAC',
    hash: 'SHA-512',
    minSecretBytes: 64,
    kty: 'oct',
    label: 'HMAC using SHA-512',
  },
  RS256: {
    family: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    kty: 'RSA',
    label: 'RSASSA-PKCS1-v1_5 using SHA-256',
  },
  RS384: {
    family: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-384',
    kty: 'RSA',
    label: 'RSASSA-PKCS1-v1_5 using SHA-384',
  },
  RS512: {
    family: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-512',
    kty: 'RSA',
    label: 'RSASSA-PKCS1-v1_5 using SHA-512',
  },
  PS256: {
    family: 'RSA-PSS',
    hash: 'SHA-256',
    saltLength: 32,
    kty: 'RSA',
    label: 'RSASSA-PSS using SHA-256',
  },
  PS384: {
    family: 'RSA-PSS',
    hash: 'SHA-384',
    saltLength: 48,
    kty: 'RSA',
    label: 'RSASSA-PSS using SHA-384',
  },
  PS512: {
    family: 'RSA-PSS',
    hash: 'SHA-512',
    saltLength: 64,
    kty: 'RSA',
    label: 'RSASSA-PSS using SHA-512',
  },
  ES256: {
    family: 'ECDSA',
    hash: 'SHA-256',
    curve: 'P-256',
    signatureBytes: 64,
    kty: 'EC',
    label: 'ECDSA using P-256 and SHA-256',
  },
  ES384: {
    family: 'ECDSA',
    hash: 'SHA-384',
    curve: 'P-384',
    signatureBytes: 96,
    kty: 'EC',
    label: 'ECDSA using P-384 and SHA-384',
  },
  ES512: {
    family: 'ECDSA',
    hash: 'SHA-512',
    curve: 'P-521',
    signatureBytes: 132,
    kty: 'EC',
    label: 'ECDSA using P-521 and SHA-512',
  },
  EdDSA: { family: 'Ed25519', kty: 'OKP', label: 'EdDSA (Ed25519)' },
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS);
export const MAX_JWKS_BYTES = 512 * 1024;

interface Candidate {
  key: CryptoKey;
  description: string;
}

class VerificationError extends Error {}

export function getSubtle(): SubtleCrypto | null {
  return globalThis.crypto?.subtle ?? null;
}

/**
 * Real cryptographic verification with the Web Crypto API. No network access is
 * performed except an explicit, user-triggered JWKS download (which never
 * includes the token).
 */
@Injectable({ providedIn: 'root' })
export class JwtSignatureService {
  private readonly decoder = inject(JwtDecoderService);
  private readonly clock = inject(ClockService);

  async verify(rawToken: string, key: KeyMaterial): Promise<SignatureResult> {
    const decoded = this.decoder.decode(rawToken);
    const base = {
      alg: decoded.alg,
      details: [] as string[],
      warnings: [] as string[],
      checkedAt: this.clock.now(),
    };
    const result = (
      status: SignatureStatus,
      title: string,
      message: string,
      extra: Partial<SignatureResult> = {},
    ): SignatureResult => ({
      ...base,
      status,
      title,
      message,
      ...extra,
      details: [...base.details, ...(extra.details ?? [])],
      warnings: [...base.warnings, ...(extra.warnings ?? [])],
    });

    if (!decoded.decoded || decoded.kind !== 'jws' || !decoded.segments || !decoded.header) {
      const reason =
        decoded.issues.find((i) => i.severity === 'error')?.message ??
        'The token could not be decoded.';
      return result('error', 'Verification Error', reason);
    }
    const alg = decoded.alg ?? '';
    if (alg.toLowerCase() === 'none') {
      return result(
        'invalid',
        'Unsigned Token',
        'The token declares alg "none" and carries no signature. It must never be accepted by a resource server.',
      );
    }
    const spec = ALGORITHMS[alg];
    if (!spec) {
      return result(
        'unsupported',
        'Unsupported Algorithm',
        `Algorithm "${alg}" is not supported by TokenScope. Supported: ${SUPPORTED_ALGORITHMS.join(', ')}.`,
      );
    }
    const subtle = getSubtle();
    if (!subtle) {
      return result(
        'error',
        'Verification Error',
        'The Web Crypto API is unavailable. It requires a secure context (HTTPS or localhost).',
      );
    }

    for (const param of ['jku', 'x5u', 'jwk'] as const) {
      if (param in decoded.header) {
        base.warnings.push(
          `The header contains "${param}". TokenScope never trusts or fetches keys referenced by the token itself.`,
        );
      }
    }
    base.details.push(`Algorithm: ${alg} — ${spec.label}`);
    base.details.push(
      `Signing input: base64url(header) + "." + base64url(payload) (${decoded.segments.header.length + decoded.segments.payload.length + 1} bytes)`,
    );

    let signature: Uint8Array;
    try {
      signature = base64UrlToBytes(decoded.segments.signature);
    } catch {
      return result('error', 'Verification Error', 'The signature segment is not valid Base64URL.');
    }
    base.details.push(`Signature length: ${signature.length} bytes`);
    if (spec.signatureBytes && signature.length !== spec.signatureBytes) {
      return result(
        'invalid',
        'Invalid Signature',
        `${alg} signatures must be exactly ${spec.signatureBytes} bytes (raw R||S), got ${signature.length}. DER-encoded ECDSA signatures are not valid in JWS.`,
      );
    }

    let candidates: Candidate[];
    try {
      candidates = await this.importCandidates(
        key,
        alg,
        spec,
        typeof decoded.header['kid'] === 'string' ? (decoded.header['kid'] as string) : null,
        base.warnings,
      );
    } catch (e) {
      if (e instanceof VerificationError) {
        return result('error', 'Verification Error', e.message);
      }
      return result(
        'error',
        'Verification Error',
        `The key could not be imported: ${(e as Error).message || 'unsupported key format'}.`,
      );
    }

    const data = utf8(`${decoded.segments.header}.${decoded.segments.payload}`);
    for (const candidate of candidates) {
      try {
        const ok = await subtle.verify(
          this.verifyParams(spec),
          candidate.key,
          toArrayBuffer(signature),
          toArrayBuffer(data),
        );
        if (ok) {
          return result(
            'verified',
            'Signature Verified',
            `The signature is mathematically valid for the provided key (${candidate.description}).`,
            {
              keyDescription: candidate.description,
              warnings: [
                'A valid signature only proves integrity with this key. Servers also check trusted issuers/keys, expiration, audience and authorization rules.',
              ],
            },
          );
        }
      } catch (e) {
        if (candidates.length === 1) {
          return result(
            'error',
            'Verification Error',
            `Web Crypto rejected the operation: ${(e as Error).message}`,
          );
        }
      }
    }
    const tried = candidates.map((c) => c.description).join('; ');
    return result(
      'invalid',
      'Invalid Signature',
      `The signature does not match the provided key. The token may have been modified, or it was signed with a different key.`,
      {
        keyDescription: tried,
        details: [`Keys tried: ${tried}`],
      },
    );
  }

  /** Downloads a JWKS document over HTTPS. The token is never sent. */
  async fetchJwks(url: string, timeoutMs = 8000): Promise<JwksFetchResult> {
    let parsed: URL;
    try {
      parsed = new URL(url.trim());
    } catch {
      return { ok: false, url, error: 'The JWKS URL is not a valid absolute URL.' };
    }
    const isLocalhost = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocalhost)) {
      return {
        ok: false,
        url,
        error: 'Only HTTPS JWKS endpoints are allowed (plain HTTP is accepted for localhost only).',
      };
    }
    if (parsed.username || parsed.password) {
      return { ok: false, url, error: 'URLs with embedded credentials are not allowed.' };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(parsed.toString(), {
        method: 'GET',
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        redirect: 'error',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      if (!response.ok) {
        return { ok: false, url, error: `The JWKS endpoint answered HTTP ${response.status}.` };
      }
      const length = Number(response.headers.get('content-length') ?? '0');
      if (length > MAX_JWKS_BYTES) {
        return { ok: false, url, error: 'The JWKS response is too large (limit 512 KB).' };
      }
      const text = await response.text();
      if (text.length > MAX_JWKS_BYTES) {
        return { ok: false, url, error: 'The JWKS response is too large (limit 512 KB).' };
      }
      const json: unknown = JSON.parse(text);
      if (!isPlainObject(json) || !Array.isArray(json['keys'])) {
        return { ok: false, url, error: 'The response is not a JWK Set (missing "keys" array).' };
      }
      return { ok: true, url, json: JSON.stringify(json, null, 2), keyCount: json['keys'].length };
    } catch (e) {
      if ((e as Error).name === 'AbortError') {
        return { ok: false, url, error: `The request timed out after ${timeoutMs / 1000}s.` };
      }
      if (e instanceof SyntaxError) {
        return { ok: false, url, error: 'The response is not valid JSON.' };
      }
      return {
        ok: false,
        url,
        error:
          'The request was blocked by the browser (CORS policy, redirect or network error). The endpoint must allow cross-origin GET requests; TokenScope does not use proxies.',
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private verifyParams(spec: AlgSpec): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
    switch (spec.family) {
      case 'RSA-PSS':
        return { name: 'RSA-PSS', saltLength: spec.saltLength! };
      case 'ECDSA':
        return { name: 'ECDSA', hash: spec.hash! };
      default:
        return { name: spec.family };
    }
  }

  private importParams(
    spec: AlgSpec,
  ): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams {
    switch (spec.family) {
      case 'HMAC':
        return { name: 'HMAC', hash: spec.hash! };
      case 'RSASSA-PKCS1-v1_5':
      case 'RSA-PSS':
        return { name: spec.family, hash: spec.hash! };
      case 'ECDSA':
        return { name: 'ECDSA', namedCurve: spec.curve! };
      case 'Ed25519':
        return { name: 'Ed25519' };
    }
  }

  private async importCandidates(
    key: KeyMaterial,
    alg: string,
    spec: AlgSpec,
    kid: string | null,
    warnings: string[],
  ): Promise<Candidate[]> {
    const subtle = getSubtle()!;
    switch (key.type) {
      case 'secret': {
        if (spec.family !== 'HMAC') {
          throw new VerificationError(
            `${alg} is an asymmetric algorithm — provide a public key (PEM, JWK or JWKS), not a shared secret.`,
          );
        }
        if (!key.value) throw new VerificationError('The secret is empty.');
        let bytes: Uint8Array;
        try {
          bytes =
            key.encoding === 'utf8'
              ? utf8(key.value)
              : key.encoding === 'base64'
                ? base64ToBytes(key.value)
                : base64UrlToBytes(key.value.trim());
        } catch {
          throw new VerificationError(
            `The secret is not valid ${key.encoding === 'base64' ? 'Base64' : 'Base64URL'}.`,
          );
        }
        if (spec.minSecretBytes && bytes.length < spec.minSecretBytes) {
          warnings.push(
            `The secret has ${bytes.length * 8} bits. RFC 7518 requires at least ${spec.minSecretBytes * 8} bits for ${alg}; libraries such as Nimbus (Spring Security) reject shorter keys.`,
          );
        }
        const cryptoKey = await subtle.importKey(
          'raw',
          toArrayBuffer(bytes),
          this.importParams(spec),
          false,
          ['verify'],
        );
        return [
          {
            key: cryptoKey,
            description: `shared secret (${bytes.length * 8} bits, ${key.encoding})`,
          },
        ];
      }
      case 'pem': {
        if (spec.family === 'HMAC') {
          throw new VerificationError(
            `${alg} uses a shared secret. Verifying an HMAC token with a public key is the classic "algorithm confusion" attack pattern and is refused.`,
          );
        }
        let block;
        try {
          block = parsePem(key.value);
        } catch (e) {
          throw new VerificationError((e as Error).message);
        }
        if (block.label.includes('PRIVATE')) {
          throw new VerificationError(
            'A private key was provided. Never paste private keys into tools — verification only needs the public key.',
          );
        }
        let spki: Uint8Array;
        if (block.label === 'PUBLIC KEY') spki = block.der;
        else if (block.label === 'RSA PUBLIC KEY') spki = wrapPkcs1RsaPublicKey(block.der);
        else if (block.label === 'CERTIFICATE') {
          try {
            spki = extractSpkiFromCertificate(block.der);
          } catch (e) {
            throw new VerificationError((e as Error).message);
          }
          warnings.push(
            'The public key was extracted from the certificate. The certificate chain, validity period and revocation status were not validated.',
          );
        } else
          throw new VerificationError(
            `Unsupported PEM block "${block.label}". Use PUBLIC KEY, RSA PUBLIC KEY or CERTIFICATE.`,
          );
        try {
          const cryptoKey = await subtle.importKey(
            'spki',
            toArrayBuffer(spki),
            this.importParams(spec),
            true,
            ['verify'],
          );
          return [
            {
              key: cryptoKey,
              description:
                `PEM ${block.label.toLowerCase()} ${await this.describeKey(cryptoKey, warnings)}`.trim(),
            },
          ];
        } catch {
          throw new VerificationError(
            `The PEM key is not compatible with ${alg} (${spec.label}). Check that the key type matches the algorithm.`,
          );
        }
      }
      case 'jwk':
      case 'jwks': {
        let json: unknown;
        try {
          json = JSON.parse(key.value);
        } catch {
          throw new VerificationError(
            `The ${key.type === 'jwk' ? 'JWK' : 'JWKS'} is not valid JSON.`,
          );
        }
        let jwks: Record<string, unknown>[];
        if (isPlainObject(json) && Array.isArray(json['keys'])) {
          jwks = json['keys'].filter(isPlainObject);
        } else if (isPlainObject(json) && typeof json['kty'] === 'string') {
          jwks = [json];
        } else {
          throw new VerificationError(
            'Expected a JWK object (with "kty") or a JWK Set (with "keys").',
          );
        }
        if (jwks.length === 0) throw new VerificationError('The JWK Set contains no keys.');

        let selected = jwks;
        if (kid && jwks.length > 1) {
          selected = jwks.filter((k) => k['kid'] === kid);
          if (selected.length === 0) {
            throw new VerificationError(
              `No key with kid "${kid}" was found in the JWK Set (${jwks.length} keys available). The server would most likely reject this token with 401.`,
            );
          }
        } else if (kid && jwks.length === 1 && jwks[0]['kid'] && jwks[0]['kid'] !== kid) {
          warnings.push(
            `The token kid "${kid}" differs from the JWK kid "${String(jwks[0]['kid'])}". A server selecting keys by kid would not use this key.`,
          );
        }
        const reasons: string[] = [];
        const candidates: Candidate[] = [];
        for (const jwk of selected) {
          const label = `JWK${jwk['kid'] ? ` kid="${String(jwk['kid'])}"` : ''}`;
          const problem = this.checkJwk(jwk, alg, spec);
          if (problem) {
            reasons.push(`${label}: ${problem}`);
            continue;
          }
          if ('d' in jwk)
            warnings.push(
              `${label} contains private key material ("d"). Only its public parameters were used — never share private JWKs.`,
            );
          try {
            const cryptoKey = await subtle.importKey(
              'jwk',
              this.publicJwk(jwk),
              this.importParams(spec),
              true,
              ['verify'],
            );
            candidates.push({
              key: cryptoKey,
              description: `${label} ${await this.describeKey(cryptoKey, warnings)}`.trim(),
            });
          } catch (e) {
            reasons.push(`${label}: import failed (${(e as Error).message})`);
          }
        }
        if (candidates.length === 0) {
          throw new VerificationError(`No usable key for ${alg}. ${reasons.join(' ')}`);
        }
        return candidates;
      }
    }
  }

  private checkJwk(jwk: Record<string, unknown>, alg: string, spec: AlgSpec): string | null {
    if (jwk['kty'] !== spec.kty)
      return `key type "${String(jwk['kty'])}" cannot verify ${alg} (expected "${spec.kty}").`;
    if (typeof jwk['alg'] === 'string' && jwk['alg'] !== alg)
      return `declares alg "${jwk['alg']}" but the token uses "${alg}".`;
    if (typeof jwk['use'] === 'string' && jwk['use'] !== 'sig')
      return `"use" is "${jwk['use']}", not "sig".`;
    if (Array.isArray(jwk['key_ops']) && !jwk['key_ops'].includes('verify'))
      return '"key_ops" does not allow "verify".';
    if (spec.kty === 'EC' && jwk['crv'] !== spec.curve)
      return `curve "${String(jwk['crv'])}" does not match ${alg} (${spec.curve}).`;
    if (spec.kty === 'OKP' && jwk['crv'] !== 'Ed25519')
      return `curve "${String(jwk['crv'])}" is not supported (Ed25519 only).`;
    return null;
  }

  private publicJwk(jwk: Record<string, unknown>): JsonWebKey {
    const pick = (keys: string[]) =>
      Object.fromEntries(keys.filter((k) => k in jwk).map((k) => [k, jwk[k]])) as JsonWebKey;
    switch (jwk['kty']) {
      case 'RSA':
        return pick(['kty', 'n', 'e']);
      case 'EC':
        return pick(['kty', 'crv', 'x', 'y']);
      case 'OKP':
        return pick(['kty', 'crv', 'x']);
      default:
        return pick(['kty', 'k']);
    }
  }

  private async describeKey(key: CryptoKey, warnings: string[]): Promise<string> {
    const algorithm = key.algorithm as RsaHashedKeyAlgorithm & EcKeyAlgorithm;
    if (algorithm.modulusLength) {
      if (algorithm.modulusLength < 2048)
        warnings.push(
          `The RSA key has only ${algorithm.modulusLength} bits. At least 2048 bits are recommended.`,
        );
      return `(RSA ${algorithm.modulusLength}-bit)`;
    }
    if (algorithm.namedCurve) return `(EC ${algorithm.namedCurve})`;
    return `(${algorithm.name})`;
  }
}
