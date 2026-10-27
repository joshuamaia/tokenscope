import { Injectable, inject } from '@angular/core';
import { DecodedJwt } from '../models/jwt.models';
import { DiffEntry, deepDiff, deepEqual } from '../utils/deep-diff';
import { formatDuration, toIso } from '../utils/time-format';
import { JwtClaimsService } from './jwt-claims.service';
import { JwtPermissionService } from './jwt-permission.service';

export interface SetComparison {
  label: string;
  onlyA: string[];
  onlyB: string[];
  both: string[];
}

export interface FieldComparison {
  label: string;
  a: string;
  b: string;
  same: boolean;
}

export interface CompareResult {
  header: DiffEntry[];
  payload: DiffEntry[];
  fields: FieldComparison[];
  permissions: SetComparison[];
  summary: string[];
  stats: Record<DiffEntry['kind'], number>;
}

@Injectable({ providedIn: 'root' })
export class JwtCompareService {
  private readonly claims = inject(JwtClaimsService);
  private readonly permissions = inject(JwtPermissionService);

  compare(a: DecodedJwt, b: DecodedJwt): CompareResult {
    const header = deepDiff(a.header ?? {}, b.header ?? {});
    const payload = deepDiff(a.payload ?? {}, b.payload ?? {});
    const stats = { added: 0, removed: 0, modified: 0, unchanged: 0 };
    for (const e of [...header, ...payload]) stats[e.kind]++;

    const permA = this.authorityNames(a);
    const permB = this.authorityNames(b);
    const permissions: SetComparison[] = [
      this.sets('Roles', permA.roles, permB.roles),
      this.sets('Scopes', permA.scopes, permB.scopes),
      this.sets('Authorities', permA.authorities, permB.authorities),
    ];

    const fmtTime = (v: number | null) => (v === null ? '—' : toIso(v * 1000));
    const str = (v: unknown) =>
      v === undefined ? '—' : typeof v === 'string' ? v : JSON.stringify(v);
    const expA = this.claims.numericDate(a.payload, 'exp');
    const expB = this.claims.numericDate(b.payload, 'exp');
    const fields: FieldComparison[] = [
      { label: 'Algorithm', a: a.alg ?? '—', b: b.alg ?? '—', same: a.alg === b.alg },
      {
        label: 'Issuer',
        a: str(a.payload?.['iss']),
        b: str(b.payload?.['iss']),
        same: deepEqual(a.payload?.['iss'], b.payload?.['iss']),
      },
      {
        label: 'Audience',
        a: this.claims.audiences(a.payload).join(', ') || '—',
        b: this.claims.audiences(b.payload).join(', ') || '—',
        same: deepEqual(
          [...this.claims.audiences(a.payload)].sort(),
          [...this.claims.audiences(b.payload)].sort(),
        ),
      },
      {
        label: 'Subject',
        a: str(a.payload?.['sub']),
        b: str(b.payload?.['sub']),
        same: deepEqual(a.payload?.['sub'], b.payload?.['sub']),
      },
      { label: 'Expiration', a: fmtTime(expA), b: fmtTime(expB), same: expA === expB },
      {
        label: 'Issued at',
        a: fmtTime(this.claims.numericDate(a.payload, 'iat')),
        b: fmtTime(this.claims.numericDate(b.payload, 'iat')),
        same:
          this.claims.numericDate(a.payload, 'iat') === this.claims.numericDate(b.payload, 'iat'),
      },
    ];

    return {
      header,
      payload,
      fields,
      permissions,
      summary: this.summarize(a, b, permissions, fields, expA, expB, stats),
      stats,
    };
  }

  report(result: CompareResult): string {
    const lines = [
      'TokenScope — JWT Comparison Report',
      '='.repeat(48),
      `Generated: ${new Date().toISOString()}`,
      '',
      'Summary',
      '-'.repeat(48),
    ];
    result.summary.forEach((s) => lines.push(`• ${s}`));
    lines.push('', 'Key fields', '-'.repeat(48));
    result.fields.forEach((f) =>
      lines.push(`${f.same ? '=' : '≠'} ${f.label.padEnd(12)} A: ${f.a}  |  B: ${f.b}`),
    );
    lines.push('', 'Payload differences', '-'.repeat(48));
    result.payload
      .filter((d) => d.kind !== 'unchanged')
      .forEach((d) =>
        lines.push(
          `[${d.kind.toUpperCase()}] ${d.path}: ${d.kind === 'added' ? '' : JSON.stringify(d.before)}${d.kind === 'modified' ? ' → ' : ''}${d.kind === 'removed' ? '' : JSON.stringify(d.after)}`,
        ),
      );
    const headerChanges = result.header.filter((d) => d.kind !== 'unchanged');
    if (headerChanges.length) {
      lines.push('', 'Header differences', '-'.repeat(48));
      headerChanges.forEach((d) =>
        lines.push(
          `[${d.kind.toUpperCase()}] ${d.path}: ${JSON.stringify(d.before ?? null)} → ${JSON.stringify(d.after ?? null)}`,
        ),
      );
    }
    lines.push('', 'Raw tokens and signatures are omitted.');
    return lines.join('\n');
  }

  /** Spring-style names: roles → ROLE_x, scopes → SCOPE_x, authorities as-is. */
  private authorityNames(token: DecodedJwt) {
    const p = this.permissions.extract(token.payload);
    return {
      roles: p.roles.map((r) => (r.startsWith('ROLE_') ? r : `ROLE_${r}`)),
      scopes: p.scopes.map((s) => (s.startsWith('SCOPE_') ? s : `SCOPE_${s}`)),
      authorities: p.authorities,
    };
  }

  private sets(label: string, a: string[], b: string[]): SetComparison {
    return {
      label,
      onlyA: a.filter((v) => !b.includes(v)),
      onlyB: b.filter((v) => !a.includes(v)),
      both: a.filter((v) => b.includes(v)),
    };
  }

  private summarize(
    a: DecodedJwt,
    b: DecodedJwt,
    permissions: SetComparison[],
    fields: FieldComparison[],
    expA: number | null,
    expB: number | null,
    stats: Record<DiffEntry['kind'], number>,
  ): string[] {
    const out: string[] = [];
    const list = (values: string[]) =>
      values.length === 1 ? values[0] : `${values.slice(0, -1).join(', ')} and ${values.at(-1)}`;
    for (const set of permissions) {
      if (set.onlyB.length)
        out.push(
          `Token B contains ${list(set.onlyB)}, which ${set.onlyB.length === 1 ? 'is' : 'are'} missing from Token A.`,
        );
      if (set.onlyA.length)
        out.push(
          `Token A contains ${list(set.onlyA)}, which ${set.onlyA.length === 1 ? 'is' : 'are'} missing from Token B.`,
        );
    }
    if (expA !== null && expB !== null && expA !== expB) {
      out.push(
        `Token ${expA < expB ? 'A' : 'B'} expires earlier than Token ${expA < expB ? 'B' : 'A'} (by ${formatDuration(Math.abs(expA - expB))}).`,
      );
    } else if ((expA === null) !== (expB === null)) {
      out.push(
        `Token ${expA === null ? 'A' : 'B'} has no expiration while Token ${expA === null ? 'B' : 'A'} does.`,
      );
    }
    const field = (label: string) => fields.find((f) => f.label === label)!;
    if (!field('Issuer').same) out.push('Both tokens use different issuers.');
    if (!field('Audience').same) out.push('The tokens are intended for different audiences.');
    if (!field('Algorithm').same)
      out.push(`The tokens are signed with different algorithms (${a.alg} vs ${b.alg}).`);
    out.push(
      field('Subject').same
        ? 'Both tokens belong to the same subject.'
        : 'The tokens belong to different subjects.',
    );
    out.push(
      `${stats.added} claim(s) added, ${stats.removed} removed and ${stats.modified} modified from A to B.`,
    );
    return out;
  }
}
