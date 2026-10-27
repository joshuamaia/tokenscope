import { Injectable, inject } from '@angular/core';
import { TroubleshooterPreset } from '../models/diagnosis.models';
import { JwtPayload } from '../models/jwt.models';
import { AuthorityMappingRule } from '../models/permission.models';
import { stringToBase64Url } from '../utils/base64url';
import { ClockService } from './clock.service';
import { JwtGeneratorService } from './jwt-generator.service';

/**
 * TEST-ONLY secret used to sign demo tokens locally. It is public on purpose
 * (so demos are reproducible and verifiable) and must never be used anywhere else.
 */
export const DEMO_SECRET = 'tokenscope-demo-secret-local-testing-only-not-for-production';

export const DEMO_ISSUER = 'https://auth.example.com/realms/tokenscope-demo';
export const DEMO_AUDIENCE = 'orders-api';

export const SPRING_DEFAULT_MAPPING: AuthorityMappingRule[] = [
  { claim: 'scope|scp', prefix: 'SCOPE_', delimiter: ' ' },
];
export const ROLES_MAPPING: AuthorityMappingRule = {
  claim: 'roles',
  prefix: 'ROLE_',
  delimiter: ' ',
};

export type DemoId =
  | 'valid'
  | 'expired'
  | 'missing-role'
  | 'missing-scope'
  | 'invalid-signature'
  | 'compare'
  | 'spring-mapping';

export interface DemoScenario {
  id: DemoId;
  token: string;
  tokenB?: string;
  preset?: TroubleshooterPreset;
}

/** Builds reproducible demo tokens on demand, signed locally with the demo secret. */
@Injectable({ providedIn: 'root' })
export class DemoTokenService {
  private readonly generator = inject(JwtGeneratorService);
  private readonly clock = inject(ClockService);

  async scenario(id: DemoId): Promise<DemoScenario> {
    const now = Math.floor(this.clock.now() / 1000);
    const minutes = (m: number) => now + m * 60;

    switch (id) {
      case 'valid':
        return {
          id,
          token: await this.sign(
            this.payload({
              iat: minutes(-5),
              nbf: minutes(-5),
              exp: minutes(55),
              roles: ['USER'],
              scope: 'openid profile.read orders.read',
            }),
          ),
        };

      case 'expired': {
        const token = await this.sign(
          this.payload({
            iat: minutes(-120),
            exp: minutes(-45),
            roles: ['USER'],
            scope: 'orders.read',
          }),
        );
        return {
          id,
          token,
          preset: this.preset(
            token,
            {
              httpStatus: '401',
              method: 'GET',
              endpoint: '/api/orders',
              ruleType: 'hasAuthority',
              requiredScopes: 'orders.read',
              mappingRules: SPRING_DEFAULT_MAPPING,
            },
            'Demo 2 — Expired JWT',
          ),
        };
      }

      case 'missing-role': {
        const token = await this.sign(
          this.payload({
            iat: minutes(-2),
            exp: minutes(28),
            roles: ['USER'],
            scope: 'profile.read',
          }),
        );
        return {
          id,
          token,
          preset: this.preset(
            token,
            {
              httpStatus: '403',
              method: 'GET',
              endpoint: '/api/admin/users',
              ruleType: 'hasRole',
              requiredRoles: 'ADMIN',
              mappingRules: [...SPRING_DEFAULT_MAPPING, ROLES_MAPPING],
            },
            'Demo 3 — HTTP 403: Missing Role',
          ),
        };
      }

      case 'missing-scope': {
        const token = await this.sign(
          this.payload({ iat: minutes(-1), exp: minutes(14), scope: 'openid profile.read' }),
        );
        return {
          id,
          token,
          preset: this.preset(
            token,
            {
              httpStatus: '403',
              method: 'PUT',
              endpoint: '/api/profile',
              ruleType: 'hasAuthority',
              requiredScopes: 'profile.write',
              mappingRules: SPRING_DEFAULT_MAPPING,
            },
            'Demo 4 — HTTP 403: Missing Scope',
          ),
        };
      }

      case 'invalid-signature': {
        const original = await this.sign(
          this.payload({
            iat: minutes(-3),
            exp: minutes(57),
            roles: ['USER'],
            scope: 'orders.read',
          }),
        );
        // Tamper with the payload (privilege escalation) while keeping the original signature.
        const [header, payload, signature] = original.split('.');
        const claims = JSON.parse(
          atob(payload.replace(/-/g, '+').replace(/_/g, '/')),
        ) as JwtPayload;
        claims['roles'] = ['USER', 'ADMIN'];
        const token = `${header}.${stringToBase64Url(JSON.stringify(claims))}.${signature}`;
        return {
          id,
          token,
          preset: this.preset(
            token,
            {
              httpStatus: '401',
              method: 'DELETE',
              endpoint: '/api/admin/users/42',
              ruleType: 'hasRole',
              requiredRoles: 'ADMIN',
              mappingRules: [...SPRING_DEFAULT_MAPPING, ROLES_MAPPING],
            },
            'Demo 5 — Invalid Signature',
          ),
        };
      }

      case 'compare': {
        const a = await this.sign(
          this.payload({
            iat: minutes(-5),
            exp: minutes(10),
            roles: ['USER'],
            scope: 'profile.read',
          }),
        );
        const b = await this.sign({
          ...this.payload({
            iat: minutes(-5),
            exp: minutes(55),
            roles: ['USER', 'ADMIN'],
            scope: 'profile.read profile.write',
          }),
          iss: 'https://auth.example.com/realms/tokenscope-admin',
          department: 'engineering',
        });
        return { id, token: a, tokenB: b };
      }

      case 'spring-mapping': {
        const token = await this.sign(
          this.payload({
            iat: minutes(-1),
            exp: minutes(29),
            roles: ['ADMIN'],
            scope: 'openid profile',
          }),
        );
        return {
          id,
          token,
          preset: this.preset(
            token,
            {
              httpStatus: '403',
              method: 'GET',
              endpoint: '/api/admin/reports',
              ruleType: 'hasRole',
              requiredRoles: 'ADMIN',
              mappingRules: SPRING_DEFAULT_MAPPING,
            },
            'Demo 7 — Spring Security Authority Mapping',
          ),
        };
      }
    }
  }

  private payload(claims: JwtPayload): JwtPayload {
    return {
      iss: DEMO_ISSUER,
      sub: 'user-1024',
      aud: DEMO_AUDIENCE,
      azp: 'tokenscope-web',
      name: 'Jane Developer',
      email: 'jane.developer@example.com',
      jti: this.generator.randomId(),
      ...claims,
    };
  }

  private sign(payload: JwtPayload): Promise<string> {
    return this.generator.sign(
      payload,
      { alg: 'HS256', secret: DEMO_SECRET, encoding: 'utf8' },
      { kid: 'tokenscope-demo-hs256' },
    );
  }

  private preset(
    token: string,
    input: TroubleshooterPreset['input'],
    label: string,
  ): TroubleshooterPreset {
    return {
      label,
      autoRun: true,
      verificationKey: { type: 'secret', value: DEMO_SECRET, encoding: 'utf8' },
      input: {
        token,
        expectedIssuer: DEMO_ISSUER,
        expectedAudience: DEMO_AUDIENCE,
        springMode: true,
        signatureMode: 'verify-now',
        clockSkewSeconds: 60,
        requiredRoles: '',
        requiredScopes: '',
        requiredAuthorities: '',
        customExpression: '',
        ...input,
      },
    };
  }
}
