import React from 'react';
import { 
  Box, 
  Typography, 
  IconButton, 
  Tooltip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import { Search, ExternalLink, Globe } from 'lucide-react';
import { TacticalPanel } from '../../../../components/TacticalPanel';
import { getSafeUrl } from '../../../../utils/securityUtils';
import type { Dork } from '../../types';

interface DorkSectionProps {
  dorks: Dork[];
}

export const DorkSection: React.FC<DorkSectionProps> = ({ dorks }) => {
  if (!dorks || dorks.length === 0) return null;

  return (
    <TacticalPanel title="DORKING RESULTS" icon={<Search size={18} />}>
      <List sx={{ width: '100%', p: 0 }}>
        {dorks.map((dork, index) => (
          <React.Fragment key={dork.id}>
            <ListItem 
              alignItems="flex-start"
              secondaryAction={
                <Tooltip title="Open Search Result">
                  <IconButton 
                    edge="end" 
                    component="a" 
                    href={getSafeUrl(dork.url) ?? '#'} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    sx={{ color: 'primary.main' }}
                  >
                    <ExternalLink size={18} />
                  </IconButton>
                </Tooltip>
              }
              sx={{ px: 2, py: 1.5 }}
            >
              <ListItemIcon sx={{ minWidth: 40, mt: 0.5 }}>
                <Globe size={18} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <Typography variant="subtitle2" sx={{ fontWeight: 'bold', color: 'primary.light' }}>
                    {(dork.type ?? '').toUpperCase().replace(/_/g, ' ')}
                  </Typography>
                }
                secondary={
                  <Typography
                    variant="caption"
                    sx={{ 
                      display: 'block', 
                      color: 'text.secondary',
                      mt: 0.5,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      maxWidth: '80%'
                    }}
                  >
                    {dork.url}
                  </Typography>
                }
              />
            </ListItem>
            {index < dorks.length - 1 && <Divider component="li" sx={{ borderColor: 'rgba(255, 255, 255, 0.05)' }} />}
          </React.Fragment>
        ))}
      </List>
    </TacticalPanel>
  );
};
