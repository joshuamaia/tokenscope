import { CauseConfidence, StepStatus } from '../../core/models/diagnosis.models';
import { IconName } from '../../shared/components/icon/icon.component';

export const STEP_ICON: Record<StepStatus, IconName> = {
  passed: 'circle-check',
  failed: 'circle-x',
  warning: 'alert',
  'not-verified': 'circle-help',
  'not-applicable': 'circle-minus',
};

export const CONFIDENCE_LABEL: Record<CauseConfidence, string> = {
  confirmed: 'Confirmed by local evidence',
  likely: 'Likely',
  possible: 'Hypothesis',
};

export const CONFIDENCE_HINT: Record<CauseConfidence, string> = {
  confirmed: 'Proven by the token data and the rules you configured.',
  likely: 'Strongly suggested by the token data, but depends on server configuration.',
  possible: 'Cannot be checked without access to the server — investigate manually.',
};
