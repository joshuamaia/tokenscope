import { IconName } from '../shared/components/icon/icon.component';

export interface NavItem {
  path: string;
  label: string;
  icon: IconName;
  description: string;
  highlight?: boolean;
}

export const NAV_ITEMS: NavItem[] = [
  {
    path: '/',
    label: 'Dashboard',
    icon: 'dashboard',
    description: 'Overview of every TokenScope tool',
  },
  {
    path: '/troubleshooter',
    label: 'Auth Troubleshooter',
    icon: 'stethoscope',
    description: 'Diagnose HTTP 401 / 403 failures step by step',
    highlight: true,
  },
  {
    path: '/inspector',
    label: 'JWT Inspector',
    icon: 'inspect',
    description: 'Decode header, payload and signature',
  },
  {
    path: '/security',
    label: 'Security Analyzer',
    icon: 'shield',
    description: 'Static security rules and score',
  },
  {
    path: '/timeline',
    label: 'Token Timeline',
    icon: 'clock',
    description: 'Visualize iat, nbf and exp',
  },
  {
    path: '/compare',
    label: 'JWT Compare',
    icon: 'compare',
    description: 'Deep diff between two tokens',
  },
  {
    path: '/permissions',
    label: 'Permission Explorer',
    icon: 'users',
    description: 'Roles, scopes, authorities and rules',
  },
  {
    path: '/generator',
    label: 'JWT Generator',
    icon: 'sparkles',
    description: 'Create signed HS256 / RS256 test tokens',
  },
  {
    path: '/signature',
    label: 'Signature Verifier',
    icon: 'signature',
    description: 'Verify signatures with Web Crypto',
  },
  {
    path: '/demos',
    label: 'Demo Playground',
    icon: 'flask',
    description: 'Ready-to-run scenarios',
  },
];
