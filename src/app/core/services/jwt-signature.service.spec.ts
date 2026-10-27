import { TestBed } from '@angular/core/testing';
import { NOW, configureClock, fakeToken } from '../../../testing/test-tokens';
import { bytesToBase64Url, stringToBase64Url, toArrayBuffer, utf8 } from '../utils/base64url';
import { parsePem, toPem, wrapPkcs1RsaPublicKey } from '../utils/pem';
import { JwtGeneratorService } from './jwt-generator.service';
import { JwtSignatureService } from './jwt-signature.service';

const SECRET = 'a-very-long-test-secret-of-at-least-32-bytes!!';

describe('JwtGeneratorService + JwtSignatureService', () => {
  let generator: JwtGeneratorService;
  let verifier: JwtSignatureService;
  const payload = { sub: 'u1', exp: NOW + 600 };

  beforeEach(() => {
    configureClock();
    generator = TestBed.inject(JwtGeneratorService);
    verifier = TestBed.inject(JwtSignatureService);
  });

  const tamper = (token: string) => {
    const [h, , s] = token.split('.');
    return `${h}.${stringToBase64Url(JSON.stringify({ sub: 'admin', exp: NOW + 600 }))}.${s}`;
  };

  describe('HS256', () => {
    it('generates a token that verifies with the same secret', async () => {
      const token = await generator.sign(payload, {
        alg: 'HS256',
        secret: SECRET,
        encoding: 'utf8',
      });
      expect(token.split('.')).toHaveLength(3);
      const result = await verifier.verify(token, {
        type: 'secret',
        value: SECRET,
        encoding: 'utf8',
      });
      expect(result.status).toBe('verified');
    });

    it('detects a tampered payload', async () => {
      const token = await generator.sign(payload, {
        alg: 'HS256',
        secret: SECRET,
        encoding: 'utf8',
      });
      const result = await verifier.verify(tamper(token), {
        type: 'secret',
        value: SECRET,
        encoding: 'utf8',
      });
      expect(result.status).toBe('invalid');
    });

    it('reports a wrong secret as invalid and warns about short secrets', async () => {
      const token = await generator.sign(payload, {
        alg: 'HS256',
        secret: SECRET,
        encoding: 'utf8',
      });
      const result = await verifier.verify(token, {
        type: 'secret',
        value: 'short',
        encoding: 'utf8',
      });
      expect(result.status).toBe('invalid');
      expect(result.warnings.some((w) => w.includes('RFC 7518'))).toBe(true);
    });

    it('supports Base64URL secrets produced by the generator', async () => {
      const secret = generator.generateSecret();
      const token = await generator.sign(payload, { alg: 'HS512', secret, encoding: 'base64url' });
      expect(
        (await verifier.verify(token, { type: 'secret', value: secret, encoding: 'base64url' }))
          .status,
      ).toBe('verified');
    });

    it('refuses to verify an HMAC token with a public key (algorithm confusion)', async () => {
      const pair = await generator.generateRsaKeyPair();
      const token = await generator.sign(payload, {
        alg: 'HS256',
        secret: SECRET,
        encoding: 'utf8',
      });
      const result = await verifier.verify(token, { type: 'pem', value: pair.publicPem });
      expect(result.status).toBe('error');
      expect(result.message).toContain('algorithm confusion');
    });
  });

  describe('RS256', () => {
    it('generates a token verifiable with PEM, JWK and JWKS (kid selection)', async () => {
      const pair = await generator.generateRsaKeyPair('RS256');
      const token = await generator.sign(payload, {
        alg: 'RS256',
        privateKey: pair.privateKey,
        kid: pair.kid,
      });
      expect(
        JSON.parse(atob(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')))['kid'],
      ).toBe(pair.kid);

      expect((await verifier.verify(token, { type: 'pem', value: pair.publicPem })).status).toBe(
        'verified',
      );
      expect(
        (await verifier.verify(token, { type: 'jwk', value: JSON.stringify(pair.publicJwk) }))
          .status,
      ).toBe('verified');

      const other = await generator.generateRsaKeyPair('RS256');
      const jwks = JSON.stringify({ keys: [other.publicJwk, pair.publicJwk] });
      const result = await verifier.verify(token, { type: 'jwks', value: jwks });
      expect(result.status).toBe('verified');
      expect(result.keyDescription).toContain(pair.kid);
    });

    it('accepts PKCS#1 "RSA PUBLIC KEY" PEM blocks', async () => {
      const pair = await generator.generateRsaKeyPair('RS256');
      const token = await generator.sign(payload, { alg: 'RS256', privateKey: pair.privateKey });
      const spki = parsePem(pair.publicPem).der;
      // SPKI = SEQ{ algId, BIT STRING{ 0x00, pkcs1 } } — the RSA SPKI prefix for 2048-bit keys is 24 bytes.
      const pkcs1 = spki.slice(24);
      expect(wrapPkcs1RsaPublicKey(pkcs1)).toEqual(spki);
      expect(
        (await verifier.verify(token, { type: 'pem', value: toPem(pkcs1, 'RSA PUBLIC KEY') }))
          .status,
      ).toBe('verified');
    });

    it('detects a tampered RS256 token and a wrong key', async () => {
      const pair = await generator.generateRsaKeyPair('RS256');
      const other = await generator.generateRsaKeyPair('RS256');
      const token = await generator.sign(payload, { alg: 'RS256', privateKey: pair.privateKey });
      expect(
        (await verifier.verify(tamper(token), { type: 'pem', value: pair.publicPem })).status,
      ).toBe('invalid');
      expect((await verifier.verify(token, { type: 'pem', value: other.publicPem })).status).toBe(
        'invalid',
      );
    });

    it('reports a kid missing from the JWKS', async () => {
      const pair = await generator.generateRsaKeyPair('RS256');
      const other = await generator.generateRsaKeyPair('RS256');
      const third = await generator.generateRsaKeyPair('RS256');
      const token = await generator.sign(payload, {
        alg: 'RS256',
        privateKey: pair.privateKey,
        kid: pair.kid,
      });
      const result = await verifier.verify(token, {
        type: 'jwks',
        value: JSON.stringify({ keys: [other.publicJwk, third.publicJwk] }),
      });
      expect(result.status).toBe('error');
      expect(result.message).toContain(`No key with kid "${pair.kid}"`);
    });

    it('rejects JWKs whose type or declared alg does not match', async () => {
      const pair = await generator.generateRsaKeyPair('RS256');
      const token = await generator.sign(payload, { alg: 'RS256', privateKey: pair.privateKey });
      const wrongAlg = await verifier.verify(token, {
        type: 'jwk',
        value: JSON.stringify({ ...pair.publicJwk, alg: 'RS512' }),
      });
      expect(wrongAlg.status).toBe('error');
      const wrongUse = await verifier.verify(token, {
        type: 'jwk',
        value: JSON.stringify({ ...pair.publicJwk, use: 'enc' }),
      });
      expect(wrongUse.status).toBe('error');
    });
  });

  it('verifies ES256 signatures (raw R||S)', async () => {
    const subtle = globalThis.crypto.subtle;
    const pair = (await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const input = `${stringToBase64Url(JSON.stringify({ alg: 'ES256' }))}.${stringToBase64Url(JSON.stringify(payload))}`;
    const sig = new Uint8Array(
      await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        pair.privateKey,
        toArrayBuffer(utf8(input)),
      ),
    );
    const token = `${input}.${bytesToBase64Url(sig)}`;
    const jwk = await subtle.exportKey('jwk', pair.publicKey);
    expect((await verifier.verify(token, { type: 'jwk', value: JSON.stringify(jwk) })).status).toBe(
      'verified',
    );
  });

  it('handles none, unsupported algorithms, private keys and malformed tokens', async () => {
    expect(
      (
        await verifier.verify(fakeToken(payload, { alg: 'none' }, ''), {
          type: 'secret',
          value: 'x',
          encoding: 'utf8',
        })
      ).status,
    ).toBe('invalid');
    expect(
      (
        await verifier.verify(fakeToken(payload, { alg: 'XY256' }), {
          type: 'secret',
          value: 'x',
          encoding: 'utf8',
        })
      ).status,
    ).toBe('unsupported');
    const priv = await verifier.verify(fakeToken(payload, { alg: 'RS256' }), {
      type: 'pem',
      value: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----',
    });
    expect(priv.status).toBe('error');
    expect(priv.message).toContain('private key');
    expect(
      (await verifier.verify('not-a-token', { type: 'secret', value: 'x', encoding: 'utf8' }))
        .status,
    ).toBe('error');
    expect(
      (
        await verifier.verify(fakeToken(payload, { alg: 'RS256' }), {
          type: 'secret',
          value: 'x',
          encoding: 'utf8',
        })
      ).message,
    ).toContain('asymmetric');
  });

  it('refuses non-HTTPS JWKS URLs without making a request', async () => {
    expect((await verifier.fetchJwks('http://example.com/jwks.json')).error).toContain('HTTPS');
    expect((await verifier.fetchJwks('not a url')).ok).toBe(false);
    expect((await verifier.fetchJwks('https://user:pass@example.com/jwks')).error).toContain(
      'credentials',
    );
  });
});
