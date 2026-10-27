import { Injectable, inject } from '@angular/core';
import { DecodedJwt, JwtIssue, MAX_TOKEN_LENGTH, TokenKind } from '../models/jwt.models';
import { base64UrlToBytes, base64UrlToString, isBase64Url } from '../utils/base64url';
import { isPlainObject } from '../utils/json-path';
import { JwtClaimsService } from './jwt-claims.service';

/**
 * Decodes compact JWS tokens locally. Decoding never implies the token is
 * authentic — signature verification is a separate, explicit step.
 */
@Injectable({ providedIn: 'root' })
export class JwtDecoderService {
  private readonly claims = inject(JwtClaimsService);

  /** Removes "Bearer " prefixes, surrounding quotes and any whitespace/newlines. */
  normalize(raw: string): { token: string; notes: JwtIssue[] } {
    const notes: JwtIssue[] = [];
    let token = (raw ?? '').trim();
    if (/^bearer\s+/i.test(token)) {
      token = token.replace(/^bearer\s+/i, '');
      notes.push({
        code: 'bearer-prefix',
        severity: 'info',
        segment: 'token',
        message: 'The "Bearer " prefix was removed before decoding.',
      });
    }
    if (/^["'].*["']$/s.test(token)) {
      token = token.slice(1, -1);
      notes.push({
        code: 'quoted',
        severity: 'info',
        segment: 'token',
        message: 'Surrounding quotes were removed before decoding.',
      });
    }
    if (/\s/.test(token)) {
      token = token.replace(/\s+/g, '');
      notes.push({
        code: 'whitespace',
        severity: 'warning',
        segment: 'token',
        message:
          'Whitespace or line breaks were found inside the token and removed. Servers will usually reject such tokens.',
      });
    }
    return { token, notes };
  }

  decode(raw: string): DecodedJwt {
    const result: DecodedJwt = {
      token: '',
      kind: 'empty',
      decoded: false,
      valid: false,
      segments: null,
      segmentCount: 0,
      header: null,
      payload: null,
      signatureLength: 0,
      alg: null,
      issues: [],
    };
    const error = (code: string, segment: JwtIssue['segment'], message: string) =>
      result.issues.push({ code, severity: 'error', segment, message });

    if (!raw || !raw.trim()) {
      error(
        'empty',
        'token',
        'The token is empty. Paste a compact JWT (header.payload.signature).',
      );
      return result;
    }
    if (raw.length > MAX_TOKEN_LENGTH) {
      error(
        'too-large',
        'token',
        `The input exceeds ${MAX_TOKEN_LENGTH / 1024} KB. TokenScope limits input size to protect the browser from excessive processing.`,
      );
      result.kind = 'unknown';
      return result;
    }

    const { token, notes } = this.normalize(raw);
    result.token = token;
    result.issues.push(...notes);
    const parts = token.split('.');
    result.segmentCount = parts.length;

    if (parts.length === 5) {
      result.kind = 'jwe';
      error(
        'jwe',
        'token',
        'This looks like a JWE (encrypted JWT, 5 segments). Its payload is encrypted and cannot be read without the decryption key. TokenScope inspects signed JWS tokens only.',
      );
      result.header = this.tryParseObject(parts[0]);
      result.alg =
        typeof result.header?.['alg'] === 'string' ? (result.header['alg'] as string) : null;
      return result;
    }
    if (parts.length !== 3) {
      result.kind = 'unknown';
      error(
        'segments',
        'token',
        `A compact JWS must have exactly 3 segments separated by dots — found ${parts.length}.`,
      );
      return result;
    }

    result.kind = 'jws' satisfies TokenKind;
    const [header, payload, signature] = parts;
    result.segments = { header, payload, signature };

    result.header = this.decodeSegment(header, 'header', result.issues);
    result.payload = this.decodeSegment(payload, 'payload', result.issues);

    if (signature.length > 0) {
      if (!isBase64Url(signature)) {
        error('signature-base64', 'signature', 'The signature segment is not valid Base64URL.');
      } else {
        result.signatureLength = base64UrlToBytes(signature).length;
      }
    }

    if (result.header) {
      const alg = result.header['alg'];
      if (typeof alg !== 'string' || !alg) {
        error(
          'alg-missing',
          'header',
          'The header has no valid "alg" parameter, which is required for JWS.',
        );
      } else {
        result.alg = alg;
        if (alg.toLowerCase() === 'none' && signature.length > 0) {
          error(
            'none-with-signature',
            'signature',
            'alg is "none" but a signature is present — this is an inconsistent token.',
          );
        }
        if (alg.toLowerCase() !== 'none' && signature.length === 0) {
          error(
            'signature-missing',
            'signature',
            `alg is "${alg}" but the signature segment is empty.`,
          );
        }
      }
      if ('enc' in result.header) {
        result.issues.push({
          code: 'enc-in-jws',
          severity: 'warning',
          segment: 'header',
          message: 'The header contains "enc", which is a JWE parameter — unexpected in a JWS.',
        });
      }
      if (
        'crit' in result.header &&
        !(Array.isArray(result.header['crit']) && result.header['crit'].length > 0)
      ) {
        error('crit-type', 'header', '"crit" must be a non-empty array of header parameter names.');
      }
    }

    if (result.payload) {
      result.issues.push(...this.claims.validateTypes(result.payload));
    }

    result.decoded = result.header !== null && result.payload !== null;
    result.valid = result.decoded && !result.issues.some((i) => i.severity === 'error');
    return result;
  }

  private decodeSegment(
    segment: string,
    name: 'header' | 'payload',
    issues: JwtIssue[],
  ): Record<string, unknown> | null {
    if (!segment) {
      issues.push({
        code: `${name}-empty`,
        severity: 'error',
        segment: name,
        message: `The ${name} segment is empty.`,
      });
      return null;
    }
    if (!isBase64Url(segment)) {
      const reason = /[+/=]/.test(segment)
        ? 'It contains "+", "/" or "=" characters — standard Base64 was used instead of Base64URL.'
        : 'It contains characters outside the Base64URL alphabet.';
      issues.push({
        code: `${name}-base64`,
        severity: 'error',
        segment: name,
        message: `The ${name} is not valid Base64URL. ${reason}`,
      });
      return null;
    }
    let text: string;
    try {
      text = base64UrlToString(segment);
    } catch {
      issues.push({
        code: `${name}-utf8`,
        severity: 'error',
        segment: name,
        message: `The ${name} does not decode to valid UTF-8 text.`,
      });
      return null;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      issues.push({
        code: `${name}-json`,
        severity: 'error',
        segment: name,
        message: `The ${name} is not valid JSON: ${(e as Error).message}`,
      });
      return null;
    }
    if (!isPlainObject(parsed)) {
      issues.push({
        code: `${name}-not-object`,
        severity: 'error',
        segment: name,
        message: `The ${name} must be a JSON object, got ${Array.isArray(parsed) ? 'an array' : typeof parsed}.`,
      });
      return null;
    }
    return parsed;
  }

  private tryParseObject(segment: string): Record<string, unknown> | null {
    try {
      const parsed: unknown = JSON.parse(base64UrlToString(segment));
      return isPlainObject(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
}
