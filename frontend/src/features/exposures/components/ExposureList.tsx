import React, { useMemo, useState } from 'react';
import {
  Box,
  Grid,
  Typography,
  CircularProgress,
  Chip,
  Stack,
  TablePagination,
} from '@mui/material';
import { useExposures } from '../api/useExposures';
import { ExposureCard } from './ExposureCard';
import type { Exposure } from '../types';
import { useThemeTokens } from '@/theme/useThemeTokens';
import { ExposureDetailsDrawer } from './ExposureDetailsDrawer';

const STATUS_ORDER = ['open', 'verified', 'remediated', 'false_positive'] as const;
const STATUS_LABELS: Record<string, string> = {
  open: 'OPEN',
  verified: 'VERIFIED',
  remediated: 'REMEDIATED',
  false_positive: 'FALSE POS',
};

interface StatsBarProps {
  exposures: Exposure[];
}

const ExposureStatsBar: React.FC<StatsBarProps> = ({ exposures }) => {
  const { tokens, isLight } = useThemeTokens();
  const counts = STATUS_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = exposures.filter((e) => e.status === s).length;
    return acc;
  }, {});
  const highRisk = exposures.filter((e) => e.risk_score >= 7).length;
  const statColor = (s: string) =>
    s === 'open' ? tokens.accent.error :
    s === 'verified' ? tokens.accent.warning :
    s === 'remediated' ? tokens.accent.success :
    tokens.accent.info;

  return (
    <Box
      sx={{
        mb: 3,
        p: 2,
        borderRadius: 1.5,
        bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.25)',
        border: 1,
        borderColor: 'divider',
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: 2,
      }}
    >
      {STATUS_ORDER.map((s) => (
        <Box key={s} sx={{ textAlign: 'center' }}>
          <Typography sx={{ fontSize: '1.1rem', fontWeight: 900, color: statColor(s), fontFamily: 'Orbitron' }}>
            {counts[s]}
          </Typography>
          <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 0.5 }}>
            {STATUS_LABELS[s]}
          </Typography>
        </Box>
      ))}
      <Box sx={{ textAlign: 'center', borderLeft: 1, borderColor: 'divider', pl: 2 }}>
        <Typography sx={{ fontSize: '1.1rem', fontWeight: 900, color: tokens.accent.error, fontFamily: 'Orbitron' }}>
          {highRisk}
        </Typography>
        <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 0.5 }}>
          HIGH RISK
        </Typography>
      </Box>
    </Box>
  );
};

interface ExposureListProps {
  scan_id?: string;
  target_id?: string;
}

export const ExposureList: React.FC<ExposureListProps> = ({ scan_id, target_id }) => {
  const [selectedExposure, setSelectedExposure] = useState<Exposure | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(12);
  const { tokens } = useThemeTokens();

  // Server page is 1-indexed; status filter is applied server-side when not "all"
  const { data, isLoading, isFetching, error } = useExposures({
    scan_history: scan_id,
    target_id,
    page: page + 1,
    length: rowsPerPage,
    ...(statusFilter !== 'all' ? { status: statusFilter } : {}),
  });

  // Unfiltered sample for stats bar (API max page_size is 200)
  const { data: statsData } = useExposures({
    scan_history: scan_id,
    target_id,
    page: 1,
    length: 200,
  });

  const exposures = data?.results || [];
  const totalCount = data?.count ?? 0;
  const statsExposures = statsData?.results || [];

  React.useEffect(() => {
    if (totalCount === 0) {
      if (page !== 0) setPage(0);
      return;
    }
    const maxPage = Math.max(0, Math.ceil(totalCount / rowsPerPage) - 1);
    if (page > maxPage) setPage(maxPage);
  }, [totalCount, rowsPerPage, page]);

  const filterChipCounts = useMemo(() => {
    const all = statsData?.count ?? 0;
    return {
      all,
      open: statsExposures.filter((e) => e.status === 'open').length,
      verified: statsExposures.filter((e) => e.status === 'verified').length,
      remediated: statsExposures.filter((e) => e.status === 'remediated').length,
      false_positive: statsExposures.filter((e) => e.status === 'false_positive').length,
    };
  }, [statsData?.count, statsExposures]);

  if (isLoading && !data) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Typography color="error" sx={{ p: 2 }}>
        Error loading exposures. Please try again.
      </Typography>
    );
  }

  return (
    <Box>
      {statsExposures.length > 0 && <ExposureStatsBar exposures={statsExposures} />}

      {(statsData?.count ?? 0) > 0 && (
        <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap', gap: 1 }}>
          {(['all', 'open', 'verified', 'remediated', 'false_positive'] as const).map((s) => (
            <Chip
              key={s}
              label={s === 'all' ? `ALL (${filterChipCounts.all})` : STATUS_LABELS[s]}
              size="small"
              onClick={() => {
                setStatusFilter(s);
                setPage(0);
              }}
              variant={statusFilter === s ? 'filled' : 'outlined'}
              sx={{
                height: 22,
                fontSize: '0.6rem',
                fontWeight: 700,
                fontFamily: 'Orbitron',
                cursor: 'pointer',
                ...(statusFilter === s && {
                  bgcolor: tokens.surface.secondary,
                  color: 'text.primary',
                }),
              }}
            />
          ))}
        </Stack>
      )}

      {totalCount === 0 && statusFilter === 'all' ? (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="body1" sx={{ color: 'text.secondary' }}>
            No exposures detected for this target/scan.
          </Typography>
        </Box>
      ) : totalCount === 0 ? (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="body1" sx={{ color: 'text.secondary' }}>
            No exposures match this status filter.
          </Typography>
        </Box>
      ) : (
        <>
          <Box sx={{ position: 'relative', opacity: isFetching && data ? 0.7 : 1, transition: 'opacity 0.15s' }}>
            <Grid container spacing={3}>
              {exposures.map((exposure) => (
                <Grid size={{ xs: 12, sm: 6, md: 4 }} key={exposure.id}>
                  <ExposureCard exposure={exposure} onClick={(exp) => setSelectedExposure(exp)} />
                </Grid>
              ))}
            </Grid>
          </Box>
          <TablePagination
            component="div"
            count={totalCount}
            page={page}
            onPageChange={(_e, next) => setPage(next)}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={(e) => {
              setRowsPerPage(parseInt(e.target.value, 10));
              setPage(0);
            }}
            rowsPerPageOptions={[6, 12, 24, 48]}
            sx={{
              mt: 1,
              color: 'text.secondary',
              '.MuiTablePagination-selectIcon': { color: 'text.secondary' },
            }}
          />
        </>
      )}

      {selectedExposure && (
        <ExposureDetailsDrawer exposure={selectedExposure} onClose={() => setSelectedExposure(null)} />
      )}
    </Box>
  );
};
