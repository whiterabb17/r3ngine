import React from 'react';
import type { AmassIntelConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { FlagCheckbox } from '../shared/FlagCheckbox';

interface Props {
  config: AmassIntelConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<AmassIntelConfig>) => void;
}

export const AmassIntelSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => (
  <SectionCard
    title="Amass Intel"
    description="WHOIS / infrastructure intel: other root domains tied to the target. Runs in parallel at Tier 1."
    enabled={enabled}
    onToggle={onToggle}
  >
    <FlagCheckbox
      label="Use amass config"
      hint="Runs amass intel with /root/.config/amass.ini and the data-source API keys it holds."
      checked={config.use_amass_config}
      onChange={(checked) => onChange({ use_amass_config: checked })}
    />
  </SectionCard>
);
