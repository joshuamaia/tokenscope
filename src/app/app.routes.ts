import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    title: 'TokenScope — JWT Inspector, Security Analyzer & Authentication Troubleshooter',
    data: { title: 'Dashboard' },
    loadComponent: () =>
      import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
  },
  {
    path: 'troubleshooter',
    title: 'Authentication Troubleshooter · TokenScope',
    data: { title: 'Authentication Troubleshooter' },
    loadComponent: () =>
      import('./features/authentication-troubleshooter/authentication-troubleshooter.component').then(
        (m) => m.AuthenticationTroubleshooterComponent,
      ),
  },
  {
    path: 'inspector',
    title: 'JWT Inspector · TokenScope',
    data: { title: 'JWT Inspector' },
    loadComponent: () =>
      import('./features/jwt-inspector/jwt-inspector.component').then(
        (m) => m.JwtInspectorComponent,
      ),
  },
  {
    path: 'security',
    title: 'Security Analyzer · TokenScope',
    data: { title: 'Security Analyzer' },
    loadComponent: () =>
      import('./features/security-analyzer/security-analyzer.component').then(
        (m) => m.SecurityAnalyzerComponent,
      ),
  },
  {
    path: 'timeline',
    title: 'Token Timeline · TokenScope',
    data: { title: 'Token Timeline' },
    loadComponent: () =>
      import('./features/token-timeline/token-timeline.component').then(
        (m) => m.TokenTimelineComponent,
      ),
  },
  {
    path: 'compare',
    title: 'JWT Compare · TokenScope',
    data: { title: 'JWT Compare' },
    loadComponent: () =>
      import('./features/jwt-compare/jwt-compare.component').then((m) => m.JwtCompareComponent),
  },
  {
    path: 'permissions',
    title: 'Permission Explorer · TokenScope',
    data: { title: 'Permission Explorer' },
    loadComponent: () =>
      import('./features/permission-explorer/permission-explorer.component').then(
        (m) => m.PermissionExplorerComponent,
      ),
  },
  {
    path: 'signature',
    title: 'Signature Verifier · TokenScope',
    data: { title: 'Signature Verifier' },
    loadComponent: () =>
      import('./features/signature-verifier/signature-verifier.component').then(
        (m) => m.SignatureVerifierComponent,
      ),
  },
  {
    path: 'generator',
    title: 'JWT Generator · TokenScope',
    data: { title: 'JWT Generator' },
    loadComponent: () =>
      import('./features/jwt-generator/jwt-generator.component').then(
        (m) => m.JwtGeneratorComponent,
      ),
  },
  {
    path: 'demos',
    title: 'Demo Playground · TokenScope',
    data: { title: 'Demo Playground' },
    loadComponent: () =>
      import('./features/demo-playground/demo-playground.component').then(
        (m) => m.DemoPlaygroundComponent,
      ),
  },
  { path: '**', redirectTo: '' },
];
