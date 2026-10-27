# TokenScope

**JWT Inspector, Security Analyzer & Authentication Troubleshooter — 100% in your browser.**

![Angular](https://img.shields.io/badge/Angular-22-dd0031?logo=angular)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript)
![Signals](https://img.shields.io/badge/state-Signals-7c6cff)
![Web Crypto](https://img.shields.io/badge/crypto-Web%20Crypto%20API-22d3ee)
![Tests](https://img.shields.io/badge/tests-116%20passing-2fd27a)
![Backend](https://img.shields.io/badge/backend-none-8b96b8)

TokenScope is a visual workbench for inspecting, analyzing, comparing, generating and troubleshooting JSON Web Tokens. Its centerpiece is the **Authentication Troubleshooter**, which helps developers find out *why* an API answered **HTTP 401** or **HTTP 403**. It produces an evidence-based, step-by-step diagnosis with first-class support for **Spring Security** conventions.

It goes beyond a JWT decoder: every verification is real (Web Crypto API), every simulation is labeled as such, and every diagnosis separates **confirmed evidence** from **hypotheses**.

---

## Table of contents

- [Why TokenScope](#why-tokenscope)
- [Features](#features)
- [Authentication Troubleshooter — How It Works](#authentication-troubleshooter--how-it-works)
- [Tech stack](#tech-stack)
- [Architecture](#architecture)
- [Getting started](#getting-started)
- [Running the tests](#running-the-tests)
- [Demo Playground](#demo-playground)
- [Security & privacy](#security--privacy)
- [Security Analyzer rules & score](#security-analyzer-rules--score)
- [Limitations](#limitations)

---

## Why TokenScope

A `401` or `403` from a JWT-protected API usually comes down to one of a dozen causes. These include an expired token, the wrong issuer or audience, an invalid signature, a missing role or scope, or a `ROLE_`/`SCOPE_` prefix mismatch. A common Spring-specific one is a `roles` claim that never gets mapped to authorities. Finding the culprit usually means decoding the token by hand, reading security configuration and guessing.

TokenScope automates that investigation without a backend:

- It decodes and validates the token structure.
- It verifies the signature cryptographically when you provide a key.
- It checks the time window, issuer and audience against the values you expect.
- It simulates Spring Security's `JwtGrantedAuthoritiesConverter` and the endpoint rule (`hasRole`, `hasAuthority`, …).
- It explains each result, with evidence, impact and a recommendation.

## Features

| Tool | What it does |
| --- | --- |
| **Dashboard** | Hero for the Troubleshooter with quick token input, live indicators (structure, alg, temporal state), an interactive preview and entry points to every tool. |
| **Authentication Troubleshooter** ⭐ | 10-step diagnostic pipeline for HTTP 401/403, Spring Security Analyzer, Diagnosis Summary and copyable/downloadable Diagnosis Report. |
| **JWT Inspector** | Header / payload / signature tabs, JSON syntax highlighting, colorized token segments, claim explanations (tooltips) and human-readable dates. It also runs structural validation: empty input, malformed tokens, invalid Base64URL, invalid JSON, wrong claim types, and JWE detection. |
| **Token Timeline** | Visual `iat → nbf → now → exp` timeline, live countdown, total/elapsed/remaining durations and clock-skew tolerance. Times can be shown in **UTC**, **local time** or **America/Sao_Paulo**. States: *Not Yet Valid, Within Validity Window, Expired, Missing Expiration, Invalid Temporal Claims*. |
| **Security Analyzer** | 18 documented static rules, 5 severities (Critical → Info), each with evidence, impact and recommendation. Includes a 0–100 conformance score and a configurable policy (max lifetime, required claims, allowed algorithms, clock skew). |
| **JWT Compare** | Side-by-side tokens and a deep diff of objects and arrays (*Added / Removed / Modified / Unchanged*). Compares roles, scopes and authorities, plus a smart summary (*"Token B contains ROLE_ADMIN, which is missing from Token A."*). The report can be copied. |
| **Permission Explorer** | Extracts roles, scopes and authorities from any claim path, including nested and wildcard paths (`realm_access.roles`, `resource_access.*.roles`). Includes provider presets (Keycloak, Entra ID, Okta, Auth0), an editable **permission matrix** and an authorization simulator. **Open in Authentication Troubleshooter** carries the token and rule across. |
| **JWT Generator** | Really signed **HS256/384/512** and **RS256/384/512** tokens via Web Crypto. Random test secrets, locally generated RSA-2048 key pairs (non-extractable private key), RFC 7638 `kid`, and expirations of 5 min, 15 min, 30 min, 1 h, 24 h or a custom value. Shortcuts: *Inspect / Analyze / Compare / Diagnose Generated Token*. |
| **Signature Verifier** | Verifies **HS\***, **RS\***, **PS\***, **ES\*** and **EdDSA** (where the browser supports Ed25519). Accepts a shared secret (UTF-8/Base64/Base64URL), PEM public key, PKCS#1 key or certificate, JWK, JWKS (selected by `kid`) or a **remote JWKS URL**. Statuses: *Signature Verified, Invalid Signature, Not Verified, Unsupported Algorithm, Verification Error*. |
| **Demo Playground** | Seven reproducible scenarios generated and signed locally at load time. |

All tools share an in-memory workspace built on Angular Signals, so you can send a token from one tool to another without pasting it again.

---

## Authentication Troubleshooter — How It Works

### Input

| Field | Purpose |
| --- | --- |
| JWT Token | The token from the failing request (a `Bearer ` prefix, quotes and line breaks are normalized and reported). |
| HTTP Status | `401 Unauthorized`, `403 Forbidden` or `Unknown`. Used to rank causes and check consistency. |
| Method + Endpoint | Context for the simulated rule and for hypotheses (e.g. CSRF on state-changing methods). |
| Expected Issuer / Audience | Optional; mirror `issuer-uri` and `audiences` of the resource server. |
| Required Role / Scope / Authority | Optional, comma-separated. |
| Authorization Rule | `hasRole`, `hasAnyRole`, `hasAuthority`, `hasAnyAuthority`, `hasAllAuthorities`, Custom AND, Custom OR, or a **custom Spring expression**. |
| Clock Skew | Tolerance for `exp`/`nbf` (Spring's `JwtTimestampValidator` default: 60 s). |
| Spring Security Mode | Exact `JwtGrantedAuthoritiesConverter` semantics (case-sensitive, prefixes matter) with an editable list of converters: claim, prefix and delimiter. |
| Signature Verification | *Skip*, *use the Signature Verifier result* (bound to the exact token), or *verify now* with a secret, PEM, JWK or JWKS. |

### The pipeline

| # | Step | What is checked | Typical failure |
| --- | --- | --- | --- |
| 1 | Token Structure | 3 Base64URL segments, size limit, JWE detection | Malformed or encrypted token → 401 |
| 2 | Token Decoding | Header/payload JSON objects, registered claim types | `exp` as string → 401 |
| 3 | Signature Verification | Real Web Crypto verification with *your* key; `alg: none` | Invalid signature / unknown `kid` → 401 |
| 4 | Temporal Validation | `exp`, `nbf`, `iat` with clock skew | Expired / not yet valid → 401 |
| 5 | Issuer Validation | Exact `iss` match (with trailing-slash/scheme/host hints) | Wrong realm or environment → 401 |
| 6 | Audience Validation | `aud` contains the expected audience | Token for another API → 401 |
| 7 | Claims Extraction | `roles`, `authorities`, `scope`, `scp`, `groups`, `permissions`, `realm_access.roles`, `resource_access.*.roles` | No permission claims → 403 |
| 8 | Authority Mapping | Simulated `JwtGrantedAuthoritiesConverter` → `JwtAuthenticationConverter` | Claim present but not mapped |
| 9 | Permission Evaluation | Safe parser for Spring expressions evaluated against the mapped authorities | Missing role/scope, prefix mismatch → 403 |
| 10 | Final Diagnosis | Ranks causes, sets the headline | — |

Each step reports one of **Passed**, **Failed**, **Warning**, **Not Verified** or **Not Applicable**. Expanding a step shows *what was analyzed, data used, result & evidence, possible impact, technical explanation and recommendations*.

### Analysis rules

- **Evidence levels.** Every cause is tagged:
  - **Confirmed** — proven by the token and the rules you configured. Example: `exp` is 45 minutes in the past, or `ROLE_ADMIN` is absent from the mapped authorities.
  - **Likely** — strongly suggested, but it depends on the server. Example: an unsupported `alg`, or a `kid` that is not in the JWKS.
  - **Hypothesis** — cannot be checked locally. Examples: the token was never sent, the server mapping differs, there are method-level rules, or CSRF blocks `POST`/`PUT`/`PATCH`/`DELETE`.
- **Ranking.** Confirmed → likely → hypothesis. Causes matching the reported status come first: authentication for 401, authorization for 403. Ties keep pipeline order.
- **Prefix intelligence.** Near matches are detected and reported as specific causes:
  - `ROLE_` prefix mismatch, such as `hasRole('ADMIN')` against the authority `ADMIN`.
  - `SCOPE_` prefix mismatch, such as `hasAuthority('read')` against `SCOPE_read`.
  - Case-only differences.
- **Unmapped claims.** If the required name exists in a claim that no converter reads, the cause *Permission Claim Not Mapped* is reported. It comes with a **suggested mapping fix** that you can apply and re-run in one click. The generated Java configuration is shown as well.
- **Status consistency.** A note is shown when the reported status contradicts the local evidence, e.g. 401 reported but only authorization problems found.
- **No invented evidence.** When the configuration is not enough, for example a 403 with no rule configured or a 401 with an unverified signature, the headline reads **"Insufficient Information for a Definitive Diagnosis"**.

### Simulations

Authorization results are always labeled **"Access Denied — Simulated"** or **"Access Granted — Simulated"**. The rule parser understands a safe subset of Spring Security SpEL: `hasRole`, `hasAnyRole`, `hasAllRoles`, `hasAuthority`, `hasAnyAuthority`, `hasAllAuthorities`, `permitAll`, `denyAll`, `isAuthenticated`, `isFullyAuthenticated`, `isAnonymous`, plus `and`/`or`/`not`/`&&`/`||`/`!` and parentheses. It is a hand-written recursive-descent parser: nothing is evaluated as code, length and nesting depth are limited, and unknown functions are rejected.

### Spring Security integration (conceptual)

The **Spring Security Analyzer** panel has four tabs:

- **Authority mapping**: claim → raw values → prefixed authorities for every converter, with warnings for claims no converter reads.
- **Rule evaluator**: a playground with examples (`hasRole("ADMIN")`, `hasAuthority("SCOPE_read")`, `hasAnyRole("ADMIN", "MANAGER")`, …), a plain-English interpretation and per-check results.
- **Java config**: the equivalent `JwtGrantedAuthoritiesConverter` / `JwtAuthenticationConverter` beans and the `authorizeHttpRequests` rule for the current simulation.
- **Concepts**: role vs. authority, the `ROLE_` and `SCOPE_` conventions, both converters, claim mapping, and 401 vs. 403.

### Diagnosis Report

**Copy Diagnosis Report** (or download as `.txt`) produces a plain-text report with the date, method, endpoint, status, every step, evidence, causes, hypotheses and recommendations. **The raw JWT, its signature, secrets and keys are always omitted**. Decoded claims are included only if you explicitly enable it.

### Limitations without a backend

TokenScope never sees the server's configuration, keys, filters, method security or logs. It cannot know which token was actually sent, which keys the server trusts, or whether custom validators exist. That is why it reports *simulated* decisions and explicit *hypotheses*, and never claims the server would accept or reject a token with certainty.

---

## Tech stack

- **Angular 22** with standalone components, `OnPush`, zoneless change detection and lazy-loaded routes
- **Angular Signals** for all state (`signal`, `computed`, `linkedSignal`, `toSignal`)
- **Reactive Forms**, typed with `NonNullableFormBuilder` (Troubleshooter and Generator)
- **TypeScript strict mode** plus `strictTemplates`
- **SCSS** design system with CSS custom properties (dark theme by default, optional light theme)
- **Web Crypto API** for HMAC, RSASSA-PKCS1-v1_5, RSA-PSS, ECDSA and Ed25519
- **Vitest** + jsdom through `@angular/build:unit-test`
- No UI or crypto libraries: icons, JSON highlighting, ASN.1/PEM handling, diffing and the expression parser are implemented in the project

## Architecture

```
src/app/
├── core/
│   ├── models/        # jwt, diagnosis, permission, security, signature, timeline
│   ├── services/      # all business logic — no UI code
│   │   ├── jwt-decoder.service.ts           # structural validation + decoding
│   │   ├── jwt-claims.service.ts            # claim docs, type validation
│   │   ├── jwt-timeline.service.ts          # temporal states
│   │   ├── jwt-signature.service.ts         # Web Crypto verification, JWKS fetch
│   │   ├── jwt-generator.service.ts         # HS*/RS* signing, key generation
│   │   ├── jwt-permission.service.ts        # extraction, Spring mapping, expression parser
│   │   ├── jwt-troubleshooter.service.ts    # 10-step diagnosis + report
│   │   ├── jwt-security-analyzer.service.ts # rules + score
│   │   ├── jwt-compare.service.ts           # deep diff + summary
│   │   ├── demo-token.service.ts            # reproducible demo scenarios
│   │   ├── workspace.service.ts             # shared in-memory state (Signals)
│   │   └── clock / theme / toast / clipboard
│   └── utils/         # base64url, pem (DER/X.509), deep-diff, json-path, json-tokens, time-format
├── shared/
│   ├── components/    # icon, json-viewer, token-input, copy-button, score-gauge, send-to, toast-container
│   └── directives/    # tooltip
├── layout/            # shell, sidebar, header, navigation
└── features/          # one lazy route per tool
    ├── dashboard/
    ├── authentication-troubleshooter/   # + diagnosis-pipeline, diagnosis-summary,
    │                                    #   spring-analyzer, diagnosis-report
    ├── jwt-inspector/  token-timeline/  security-analyzer/  jwt-compare/
    └── permission-explorer/  jwt-generator/  signature-verifier/  demo-playground/
```

**Design principles**

- **Logic is separated from presentation.** Components only orchestrate. Every rule lives in an injectable service with unit tests.
- **One source of time.** `ClockService` drives all temporal logic, and tests swap in a `FixedClock`.
- **Shared workspace.** `WorkspaceService` holds the active token, the comparison tokens, the last signature verification (bound to the exact token) and one-shot presets used to hand scenarios between tools.
- **Static output.** Routes are prerendered at build time (`outputMode: "static"`). No server runtime is needed.

## Getting started

Requirements: **Node.js ^22.22.3, ^24.15.0 or >= 26** (Angular 22 engines) and npm.

```bash
npm install
npm start            # http://localhost:4200
```

Production build (static files in `dist/tokenscope/browser`, deployable to any static host):

```bash
npm run build
```

> Web Crypto requires a secure context: use `localhost` during development and HTTPS in production.

## Running the tests

```bash
npm test             # single run (Vitest)
npm run test:watch   # watch mode
```

**116 tests** cover:

- **Decoding and structural validation**: empty input, segment count, JWE, Base64URL, JSON, claim types, normalization and size limit.
- **Claims and timeline**: every temporal state, clock skew, and inconsistent claims, all against a controllable clock.
- **Permissions**: nested and wildcard extraction, Spring authority mapping, the expression parser (including rejection of injection attempts), and `ROLE_`/`SCOPE_`/case near matches.
- **Security Analyzer**: every rule, the policy and score bounds.
- **JWT Compare**: deep diff and the smart summary.
- **Generation and verification**:
  - HS256 and RS256 generation; verification with PEM, PKCS#1, JWK, JWKS (`kid` selection) and ES256.
  - Tampered payloads, wrong keys and algorithm-confusion refusal.
  - Private-key refusal, `alg: none`, unsupported algorithms, and JWKS URL validation.
- **Troubleshooter scenarios**: expired, not yet valid, missing role, missing scope, issuer mismatch, audience mismatch, invalid signature, signature not verified, `ROLE_` mismatch, `SCOPE_` mismatch, insufficient configuration, and a temporally valid token without sufficient permission. Further tests cover unmapped claims, CSRF hypotheses, status consistency, and reports never leaking the token.
- **All 7 demos end to end**, plus routed UI smoke tests for every page and the main user flows.

## Demo Playground

Every demo token is generated **and signed in the browser when it is loaded**, with timestamps relative to "now". They use the public test-only HS256 secret `tokenscope-demo-secret-local-testing-only-not-for-production` (kid `tokenscope-demo-hs256`).

| Demo | Scenario | Expected result |
| --- | --- | --- |
| 1 | Valid JWT | Within Validity Window; signature verifies |
| 2 | Expired JWT | 401 · JWT Expired (confirmed) |
| 3 ⭐ | HTTP 403: Missing Role — `ROLE_USER` on `GET /api/admin/users` requiring `ROLE_ADMIN` | **Access Denied — Simulated** · Missing Required Authority |
| 4 | HTTP 403: Missing Scope — `SCOPE_profile.read` vs `SCOPE_profile.write` | Access Denied — Simulated · Insufficient Scope |
| 5 | Invalid Signature — payload escalated to ADMIN after signing | Invalid Signature (real verification) |
| 6 | JWT Comparison — different roles, scopes, issuers and expirations | Smart summary in JWT Compare |
| 7 | Spring Security Authority Mapping — `roles: ["ADMIN"]` with the default converter | Permission Claim Not Mapped → apply fix → Access Granted — Simulated |

## Security & privacy

> **Your tokens are processed locally in your browser.**

- **Local processing only.** All decoding, analysis, signing and verification run client-side. Tokens are never sent to any server.
- **Nothing is persisted.** No tokens, keys or results are stored (no `localStorage`, cookies or IndexedDB). The theme preference is the only stored value. **Clear session data** in the header wipes the in-memory workspace.
- **No tokens in URLs or logs.** Tokens are handed between tools through in-memory signals, never through route parameters, and the app does no console logging.
- **No HTML or code execution from token data.** Claims are rendered through Angular text interpolation only, JSON highlighting is a tokenizer, and there is no `eval` or `new Function`. The only `innerHTML` is the static, compile-time icon set.
- **Input limits.**
  - Tokens are limited to 64 KB, rule expressions to 2,000 characters with bounded nesting depth, and JWKS responses to 512 KB.
  - Deep diff and highlighting are depth- and size-bounded.
- **Key hygiene.**
  - Private keys pasted into the verifier are refused, and private JWK parameters are stripped before import.
  - Generated RSA private keys are non-extractable `CryptoKey`s.
  - Short HMAC secrets are flagged (RFC 7518).
  - Verifying an HMAC token with a public key (algorithm confusion) is refused.
- **Remote JWKS.**
  - The JWKS is fetched only when you click **Fetch**, and only from HTTPS URLs (plain HTTP is accepted for localhost only).
  - The request uses `credentials: "omit"`, `no-referrer`, a timeout and no redirects, and it never contains the JWT.
  - The endpoint must allow CORS. No proxy is used.
  - URLs that come from the token itself (`jku`, `x5u`, `jwk`) are **never** trusted or fetched.
- **A valid signature is not authentication.** The UI states that a mathematically valid signature only proves integrity under the provided key.

## Security Analyzer rules & score

| Rule | Check | Severity |
| --- | --- | --- |
| TS-01 | Algorithm `none` | Critical |
| TS-02 | Missing expiration (`exp`) | High |
| TS-03 | Token expired | Medium |
| TS-04 | Token not yet valid | Low |
| TS-05 | Lifetime above the policy maximum (High if > 24 h) | Medium |
| TS-06 | `iat` later than `exp` | High |
| TS-07 | `nbf` later than `exp` | High |
| TS-08 | `iat` in the future | Medium |
| TS-09 | Missing issuer (`iss`) | Medium |
| TS-10 | Missing audience (`aud`) | Medium |
| TS-11 | Missing subject (`sub`) | Low |
| TS-12 | Invalid temporal claims (type or milliseconds) | High |
| TS-13 | Unsupported or unknown algorithm | High |
| TS-14 | Unrecognized critical (`crit`) header parameters | High |
| TS-15 | Policy violation (required claims, allowed algorithms) | Medium |
| TS-16 | Key referenced by the header (`jku`, `x5u`, `jwk`) | Medium |
| TS-17 | Sensitive data in the payload (`password`, `secret`, …) | High |
| TS-18 | Symmetric algorithm (shared secret) | Info |

**Score** = `100 − Σ penalties`, where Critical = 40, High = 20, Medium = 10, Low = 5 and Info = 0, with a minimum of 0. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40. The score measures conformance with a static analysis policy. **It is not a security guarantee.**

## Limitations

- **Simulated authorization.** TokenScope approximates Spring Security's semantics from the converters and rules you describe. It cannot read your real `SecurityFilterChain`, method security, custom `AuthorizationManager`s or filters.
- **JWS only.** JWE tokens are detected and reported but not decrypted. Nested JWTs are not unwrapped.
- **Certificates.** For X.509 certificates, only the public key is extracted. The chain, validity period and revocation status are not validated.
- **Browser algorithm support.** EdDSA verification works only in browsers whose Web Crypto implements Ed25519. The generator signs HS256/384/512 and RS256/384/512.
- **Remote JWKS** depends on the endpoint's CORS policy. Many identity providers allow it, some do not, and TokenScope deliberately uses no proxy.
- **Expression subset.** Arbitrary SpEL, such as bean references, `#oauth2` helpers or custom methods, is not supported and is reported as a parse error.

---

Built with Angular as a portfolio project for developers who debug authentication for a living.
