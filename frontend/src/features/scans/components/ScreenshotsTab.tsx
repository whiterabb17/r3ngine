import React, { useState } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Grid,
  IconButton,
  Modal,
  Backdrop,
  Fade,
} from '@mui/material';
import { X, ExternalLink, Camera } from 'lucide-react';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useScanScreenshots, type ScreenshotEntry } from '../api/scanResults';

interface ScreenshotsTabProps {
  projectSlug: string;
  scanId: number;
}

export const ScreenshotsTab: React.FC<ScreenshotsTabProps> = ({ scanId }) => {
  const { tokens } = useThemeTokens();
  const { data: subdomainData, isLoading, isError } = useScanScreenshots(scanId);
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null);
  const [lightboxLabel, setLightboxLabel] = useState<string>('');

  // Flatten all screenshots from all subdomains
  const screenshots = React.useMemo(() => {
    if (!subdomainData) return [];
    
    const flattened: (ScreenshotEntry & { subdomain_name: string })[] = [];
    
    subdomainData.forEach(sub => {
      if (sub.screenshots && sub.screenshots.length > 0) {
        sub.screenshots.forEach(s => {
          flattened.push({
            ...s,
            subdomain_name: sub.name,
            // Fallback to subdomain status if not present in screenshot
            status_code: s.status_code || sub.http_status
          });
        });
      } else if (sub.screenshot_path) {
        // Fallback for cases where screenshots array might be empty but screenshot_path exists
        flattened.push({
          id: `legacy-${sub.id}`,
          screenshot_path: sub.screenshot_path,
          url: sub.http_url || `http://${sub.name}`,
          title: sub.name,
          status_code: sub.http_status,
          subdomain_name: sub.name
        });
      }
    });
    
    return flattened;
  }, [subdomainData]);

  const openLightbox = (path: string, label: string) => {
    setLightboxSrc(`/media/${path}`);
    setLightboxLabel(label);
  };

  const closeLightbox = () => {
    setLightboxSrc(null);
    setLightboxLabel('');
  };

  return (
    <Box sx={{ width: '100%' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, alignItems: { xs: 'flex-start', sm: 'center' }, gap: 1.5, mb: 4, mt: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Camera size={20} color={tokens.accent.primary} />
          <Box>
            <Typography variant="h5" sx={{
              fontWeight: 900,
              fontFamily: 'Orbitron',
              letterSpacing: { xs: 1, sm: 3 },
              color: 'text.primary',
              textTransform: 'uppercase',
              fontSize: { xs: '1.2rem', sm: '1.5rem' }
            }}>
              Visual Intelligence
            </Typography>
            <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
              EYEWITNESS CAPTURE RESULTS
            </Typography>
          </Box>
        </Box>
      </Box>

      <TacticalPanel>
        {/* Stats bar */}
        <Box sx={{
          p: 2,
          display: 'flex',
          flexDirection: { xs: 'column', md: 'row' },
          alignItems: { xs: 'flex-start', md: 'center' },
          justifyContent: 'space-between',
          borderBottom: 1, borderColor: 'divider',
          bgcolor: 'action.hover',
          gap: 2
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Typography sx={{ fontSize: '11px', fontWeight: 600, color: 'text.secondary' }}>
                Captured:
              </Typography>
              <Box sx={{ px: 1, py: 0.5, bgcolor: `${tokens.accent.primary}14`, border: `1px solid ${tokens.accent.primary}33`, borderRadius: 1 }}>
                <Typography sx={{ fontSize: '11px', color: tokens.accent.primary, fontWeight: 700 }}>
                  {isLoading ? '...' : (screenshots?.length ?? 0)} screenshots
                </Typography>
              </Box>
              <Typography sx={{ fontSize: '11px', color: 'text.disabled' }}>
                ({subdomainData?.length ?? 0} targets)
              </Typography>
            </Box>
          </Box>
          <Typography sx={{ fontSize: '10px', color: 'text.disabled', fontFamily: 'monospace' }}>
            CLICK THUMBNAIL TO EXPAND
          </Typography>
        </Box>

        {/* Content */}
        <Box sx={{ p: 3, minHeight: 300 }}>
          {isLoading && (
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, py: 8 }}>
              <CircularProgress size={32} sx={{ color: tokens.accent.primary, filter: `drop-shadow(0 0 8px ${tokens.accent.primary})` }} />
              <Typography sx={{
                fontSize: '10px',
                fontWeight: 900,
                color: `${tokens.accent.primary}80`,
                fontFamily: 'Orbitron',
                letterSpacing: 2,
                textTransform: 'uppercase',
              }}>
                Loading Captures...
              </Typography>
            </Box>
          )}

          {isError && (
            <Box sx={{
              p: 3,
              textAlign: 'center',
              border: '1px solid rgba(255, 0, 60, 0.2)',
              borderRadius: 1,
              bgcolor: 'rgba(255, 0, 60, 0.05)',
            }}>
              <Typography sx={{ color: '#ff003c', fontFamily: 'Orbitron', fontSize: '0.75rem', fontWeight: 700 }}>
                FETCH ERROR
              </Typography>
              <Typography sx={{ color: 'text.disabled', fontSize: '0.65rem', mt: 1 }}>
                Could not load screenshots from server.
              </Typography>
            </Box>
          )}

          {!isLoading && !isError && screenshots?.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 8 }}>
              <Camera size={40} color="rgba(255,255,255,0.1)" />
              <Typography sx={{
                mt: 2,
                color: 'text.secondary',
                fontFamily: 'Orbitron',
                fontSize: '0.75rem',
                fontWeight: 700,
              }}>
                NO SCREENSHOTS CAPTURED
              </Typography>
              <Typography sx={{ color: 'text.disabled', fontSize: '0.65rem', mt: 1 }}>
                Playwright screenshot capture produced no results for this scan, or the task has not completed yet.
              </Typography>
            </Box>
          )}

          {!isLoading && !isError && screenshots && screenshots.length > 0 && (
            <Grid container spacing={2}>
              {screenshots.map((item) => (
                <Grid
                  key={item.id}
                  size={{ xs: 12, sm: 6, md: 4, lg: 3 }}
                >
                  <Box
                    onClick={() => openLightbox(item.screenshot_path, item.subdomain_name)}
                    sx={{
                      position: 'relative',
                      borderRadius: 1,
                      overflow: 'hidden',
                      border: '1px solid rgba(255,255,255,0.08)',
                      cursor: 'pointer',
                      bgcolor: 'rgba(0,0,0,0.4)',
                      transition: 'all 0.2s ease',
                      '&:hover': {
                        border: `1px solid ${tokens.accent.primary}66`,
                        boxShadow: `0 0 20px ${tokens.accent.primary}15`,
                        transform: 'translateY(-2px)',
                        '& .screenshot-overlay': { opacity: 1 },
                      },
                    }}
                  >
                    {/* Thumbnail */}
                    <Box sx={{ aspectRatio: '16/9', overflow: 'hidden', bgcolor: 'rgba(0,0,0,0.6)' }}>
                      <img
                        src={`/media/${item.screenshot_path}`}
                        alt={`Screenshot of ${item.subdomain_name}`}
                        loading="lazy"
                        style={{
                          width: '100%',
                          height: '100%',
                          objectFit: 'cover',
                          display: 'block',
                        }}
                        onError={(e) => {
                          (e.currentTarget as HTMLImageElement).style.display = 'none';
                        }}
                      />
                    </Box>

                    {/* Hover overlay */}
                    <Box
                      className="screenshot-overlay"
                      sx={{
                        position: 'absolute',
                        inset: 0,
                        bgcolor: `${tokens.accent.primary}14`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        opacity: 0,
                        transition: 'opacity 0.2s',
                      }}
                    >
                      <Typography sx={{
                        color: tokens.accent.primary,
                        fontSize: '10px',
                        fontWeight: 900,
                        fontFamily: 'Orbitron',
                        letterSpacing: 1,
                        textShadow: `0 0 10px ${tokens.accent.primary}`,
                      }}>
                        EXPAND
                      </Typography>
                    </Box>

                    {/* Footer label */}
                    <Box sx={{
                      px: 1.5,
                      py: 1,
                      borderTop: '1px solid rgba(255,255,255,0.05)',
                      bgcolor: 'rgba(0,0,0,0.4)',
                    }}>
                      <Typography sx={{
                        fontSize: '11px',
                        fontWeight: 700,
                        color: 'text.primary',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}>
                        {item.subdomain_name}
                      </Typography>
                      {item.status_code && (
                        <Typography sx={{
                          fontSize: '9px',
                          color: item.status_code < 400 ? '#00ffaa' : '#ff003c',
                          fontWeight: 700,
                          fontFamily: 'monospace',
                        }}>
                          HTTP {item.status_code}
                        </Typography>
                      )}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          )}
        </Box>
      </TacticalPanel>

      {/* Lightbox Modal */}
      <Modal
        open={!!lightboxSrc}
        onClose={closeLightbox}
        closeAfterTransition
        sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          zIndex: 999999
        }}
      >
        <Fade in={!!lightboxSrc} timeout={200}>
          <Box
            sx={{
              position: 'relative',
              width: '100vw',
              height: '100vh',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              outline: 'none',
            }}
          >
            {/* Custom Backdrop */}
            <Box 
              onClick={closeLightbox}
              sx={{ 
                position: 'absolute', 
                inset: 0, 
                bgcolor: 'rgba(0, 0, 0, 0.95)', 
                backdropFilter: 'blur(12px)', // Increased blur
                zIndex: 1,
                cursor: 'zoom-out'
              }} 
            />

            {/* Controls bar */}
            <Box
              onClick={(e) => e.stopPropagation()}
              sx={{
                position: 'relative',
                zIndex: 3,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                maxWidth: '90vw',
                mb: 2,
              }}
            >
              <Typography sx={{
                color: tokens.accent.primary,
                fontFamily: 'Orbitron',
                fontSize: '13px',
                fontWeight: 700,
                letterSpacing: 1.5,
                textShadow: `0 0 10px ${tokens.accent.primary}80`,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                maxWidth: 'calc(100% - 120px)',
              }}>
                {lightboxLabel}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1.5 }}>
                <IconButton
                  component="a"
                  href={lightboxSrc ?? '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  size="small"
                  sx={{
                    color: 'rgba(255,255,255,0.8)',
                    bgcolor: 'rgba(255,255,255,0.1)',
                    border: '1px solid rgba(255,255,255,0.2)',
                    '&:hover': { color: tokens.accent.primary, borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}15` },
                  }}
                >
                  <ExternalLink size={16} />
                </IconButton>
                <IconButton
                  onClick={closeLightbox}
                  size="small"
                  sx={{
                    color: 'rgba(255,255,255,0.8)',
                    bgcolor: 'rgba(255,255,255,0.1)',
                    border: '1px solid rgba(255,255,255,0.2)',
                    '&:hover': { color: '#ff003c', borderColor: '#ff003c', bgcolor: 'rgba(255, 0, 60, 0.1)' },
                  }}
                >
                  <X size={16} />
                </IconButton>
              </Box>
            </Box>

            {/* Image Container */}
            <Box
              onClick={(e) => e.stopPropagation()}
              sx={{
                position: 'relative',
                zIndex: 2,
                maxWidth: '92vw',
                maxHeight: '82vh',
                border: `2px solid ${tokens.accent.primary}66`,
                borderRadius: 1,
                overflow: 'hidden',
                boxShadow: `0 0 100px ${tokens.accent.primary}4D`,
                bgcolor: '#000'
              }}
            >
              {lightboxSrc && (
                <img
                  src={lightboxSrc}
                  alt={lightboxLabel}
                  style={{
                    display: 'block',
                    maxWidth: '100%',
                    maxHeight: '82vh',
                    objectFit: 'contain',
                  }}
                />
              )}
            </Box>

            {/* Dismiss hint */}
            <Typography
              onClick={closeLightbox}
              sx={{
                position: 'relative',
                zIndex: 3,
                mt: 3,
                fontSize: '11px',
                color: 'text.secondary',
                fontFamily: 'Orbitron',
                letterSpacing: 2,
                cursor: 'pointer',
                userSelect: 'none',
                '&:hover': { color: tokens.accent.primary }
              }}
            >
              CLICK ANYWHERE TO CLOSE
            </Typography>
          </Box>
        </Fade>
      </Modal>
    </Box>
  );
};
