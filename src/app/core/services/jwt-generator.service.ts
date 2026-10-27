import { Injectable } from '@angular/core';
import { JwtHeader, JwtPayload } from '../models/jwt.models';
import { SecretEncoding } from '../models/signature.models';
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64Url,
  stringToBase64Url,
  toArrayBuffer,
  utf8,
} from '../utils/base64url';
import { toPem } from '../utils/pem';
import { getSubtle } from './jwt-signature.service';

export type HmacAlg = 'HS256' | 'HS384' | 'HS512';
export type RsaAlg = 'RS256' | 'RS384' | 'RS512';
export type GeneratorAlg = HmacAlg | RsaAlg;

export type SigningKey =
  | { alg: HmacAlg; secret: string; encoding: SecretEncoding }
  | { alg: RsaAlg; privateKey: CryptoKey; kid?: string };

export interface RsaKeyPair {
  alg: RsaAlg;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicPem: string;
  publicJwk: JsonWebKey & { kid: string; alg: string; use: string };
  kid: string;
  createdAt: number;
}

const HASH: Record<GeneratorAlg, 'SHA-256' | 'SHA-384' | 'SHA-512'> = {
  HS256: 'SHA-256',
  HS384: 'SHA-384',
  HS512: 'SHA-512',
  RS256: 'SHA-256',
  RS384: 'SHA-384',
  RS512: 'SHA-512',
};

/**
 * Creates genuinely signed test tokens with Web Crypto. Keys live in memory
 * only: RSA private keys are generated as non-extractable CryptoKeys.
 */
@Injectable({ providedIn: 'root' })
export class JwtGeneratorService {
  /** Random HMAC secret encoded as Base64URL (default 256 bits). */
  generateSecret(bytes = 32): string {
    const buffer = new Uint8Array(bytes);
    crypto.getRandomValues(buffer);
    return bytesToBase64Url(buffer);
  }

  async generateRsaKeyPair(alg: RsaAlg = 'RS256', modulusLength = 2048): Promise<RsaKeyPair> {
    const subtle = this.subtle();
    const pair = (await subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: HASH[alg],
      },
      false, // private key stays non-extractable; the public key is always exportable
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
    const jwk = await subtle.exportKey('jwk', pair.publicKey);
    const kid = await this.thumbprint(jwk);
    return {
      alg,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      publicPem: toPem(spki, 'PUBLIC KEY'),
      publicJwk: { kty: 'RSA', n: jwk.n, e: jwk.e, kid, alg, use: 'sig' },
      kid,
      createdAt: Date.now(),
    };
  }

  async sign(payload: JwtPayload, key: SigningKey, extraHeader: JwtHeader = {}): Promise<string> {
    const subtle = this.subtle();
    const header: JwtHeader = { alg: key.alg, typ: 'JWT', ...extraHeader };
    if (key.alg.startsWith('RS') && 'kid' in key && key.kid && !header['kid'])
      header['kid'] = key.kid;
    const signingInput = `${stringToBase64Url(JSON.stringify(header))}.${stringToBase64Url(JSON.stringify(payload))}`;
    const data = toArrayBuffer(utf8(signingInput));

    let signature: ArrayBuffer;
    if ('secret' in key) {
      const bytes = this.secretBytes(key.secret, key.encoding);
      if (bytes.length === 0) throw new Error('The secret is empty.');
      const hmacKey = await subtle.importKey(
        'raw',
        toArrayBuffer(bytes),
        { name: 'HMAC', hash: HASH[key.alg] },
        false,
        ['sign'],
      );
      signature = await subtle.sign('HMAC', hmacKey, data);
    } else {
      signature = await subtle.sign('RSASSA-PKCS1-v1_5', key.privateKey, data);
    }
    return `${signingInput}.${bytesToBase64Url(new Uint8Array(signature))}`;
  }

  secretBytes(secret: string, encoding: SecretEncoding): Uint8Array {
    if (encoding === 'utf8') return utf8(secret);
    return encoding === 'base64' ? base64ToBytes(secret) : base64UrlToBytes(secret.trim());
  }

  randomId(): string {
    const bytes = new Uint8Array(12);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
  }

  /** RFC 7638 JWK thumbprint (SHA-256), used as a deterministic kid. */
  private async thumbprint(jwk: JsonWebKey): Promise<string> {
    const canonical = JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n });
    const digest = await this.subtle().digest('SHA-256', toArrayBuffer(utf8(canonical)));
    return bytesToBase64Url(new Uint8Array(digest)).slice(0, 16);
  }

  private subtle(): SubtleCrypto {
    const subtle = getSubtle();
    if (!subtle)
      throw new Error(
        'The Web Crypto API is unavailable. It requires a secure context (HTTPS or localhost).',
      );
    return subtle;
  }
}
