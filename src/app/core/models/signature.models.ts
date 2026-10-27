export type SignatureStatus = 'verified' | 'invalid' | 'not-verified' | 'unsupported' | 'error';

export type SecretEncoding = 'utf8' | 'base64' | 'base64url';

export type KeyMaterial =
  | { type: 'secret'; value: string; encoding: SecretEncoding }
  | { type: 'pem'; value: string }
  | { type: 'jwk'; value: string }
  | { type: 'jwks'; value: string; source?: string };

export type KeyMaterialType = KeyMaterial['type'];

export interface SignatureResult {
  status: SignatureStatus;
  alg: string | null;
  title: string;
  message: string;
  details: string[];
  warnings: string[];
  keyDescription?: string;
  checkedAt: number;
}

export const SIGNATURE_STATUS_LABEL: Record<SignatureStatus, string> = {
  verified: 'Signature Verified',
  invalid: 'Invalid Signature',
  'not-verified': 'Not Verified',
  unsupported: 'Unsupported Algorithm',
  error: 'Verification Error',
};

export interface JwksFetchResult {
  ok: boolean;
  url: string;
  json?: string;
  keyCount?: number;
  error?: string;
}
