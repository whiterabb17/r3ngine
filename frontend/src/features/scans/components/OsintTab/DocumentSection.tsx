import React from 'react';
import { 
  Box, 
  Typography, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow, 
  Chip
} from '@mui/material';
import { FileText, Monitor, User as UserIcon, Calendar } from 'lucide-react';
import { TacticalPanel } from '../../../../components/TacticalPanel';
import { getSafeUrl } from '../../../../utils/securityUtils';
import type { MetafinderDocument } from '../../types';

interface DocumentSectionProps {
  documents: MetafinderDocument[];
}

export const DocumentSection: React.FC<DocumentSectionProps> = ({ documents }) => {
  if (!documents || documents.length === 0) return null;

  return (
    <TacticalPanel title="DOCUMENT METADATA" icon={<FileText size={18} />}>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold' }}>DOCUMENT / SOURCE</TableCell>
              <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold' }}>AUTHOR / CREATOR</TableCell>
              <TableCell sx={{ display: { xs: 'none', md: 'table-cell' }, color: 'text.secondary', fontWeight: 'bold' }}>SOFTWARE / OS</TableCell>
              <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' }, color: 'text.secondary', fontWeight: 'bold' }}>DATE</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {documents.map((doc) => (
              <TableRow key={doc.id} hover>
                <TableCell sx={{ maxWidth: 300 }}>
                  <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                    {doc.doc_name || doc.title || 'Untitled Document'}
                  </Typography>
                  {doc.url && (
                    <Typography 
                      variant="caption" 
                      component="a" 
                      href={getSafeUrl(doc.url) ?? '#'} 
                      target="_blank" 
                      sx={{ color: 'primary.main', textDecoration: 'none', '&:hover': { textDecoration: 'underline' } }}
                    >
                      Source URL
                    </Typography>
                  )}
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                    {doc.author && (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <UserIcon size={12} />
                        <Typography variant="body2">{doc.author}</Typography>
                      </Box>
                    )}
                    {doc.creator && (
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                        via {doc.creator}
                      </Typography>
                    )}
                  </Box>
                </TableCell>
                <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                    {doc.os && (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Monitor size={12} />
                        <Typography variant="body2">{doc.os}</Typography>
                      </Box>
                    )}
                    {doc.producer && (
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                        {doc.producer}
                      </Typography>
                    )}
                  </Box>
                </TableCell>
                <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                  {doc.creation_date && (
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Calendar size={12} />
                      <Typography variant="body2">{doc.creation_date}</Typography>
                    </Box>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </TacticalPanel>
  );
};
