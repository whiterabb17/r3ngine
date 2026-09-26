import React, { useRef } from 'react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import {
    Box,
    Card,
    CardContent,
    Typography,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    useTheme,
    Tooltip,
    styled,
    IconButton
} from '@mui/material';
import { Globe, Plus } from 'lucide-react';
import { MapContainer, TileLayer, GeoJSON, Marker, Tooltip as LeafletTooltip } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { scaleLinear } from 'd3-scale';
import { countryCentroids } from '../types/countryCentroids';

// Pulsing Dot is now handled via global CSS .map-marker-pulse in index.css

interface CountryData {
    name: string;
    iso: string;
    count: number;
}

interface GeoJSONFeature {
    type: 'Feature';
    properties: Record<string, any>;
    geometry: any;
}

interface GeoJSONFeatureCollection {
    type: 'FeatureCollection';
    features: GeoJSONFeature[];
}

export const GeoMap: React.FC<{ data: CountryData[]; disableCard?: boolean }> = ({ data, disableCard = false }) => {
    const { theme, isLight, tokens } = useThemeTokens();
    const mapRef = useRef<L.Map>(null);
    const geoJsonRef = useRef<GeoJSONFeatureCollection | null>(null);

    const maxCount = data && data.length > 0 ? Math.max(...data.map(d => d.count), 1) : 1;
    const colorScale = scaleLinear<string>()
        .domain([0, maxCount])
        .range(["rgba(0, 243, 255, 0.05)", "rgba(0, 243, 255, 0.4)"]);

    const findCountry = (properties: any) => {
        const geoName = (properties.name || "").toUpperCase();
        return data.find(d =>
            d.iso.toUpperCase() === geoName ||
            d.name.toUpperCase() === geoName ||
            (d.name.toUpperCase() === "UNITED STATES" && geoName === "UNITED STATES OF AMERICA") ||
            (d.iso.toUpperCase() === "GB" && geoName === "UNITED KINGDOM")
        );
    };

    const onEachFeature = (feature: GeoJSONFeature, layer: L.Layer) => {
        const country = findCountry(feature.properties);
        const pathLayer = layer as L.Path;

        if (country) {
            const fillColor = colorScale(country.count);
            pathLayer.setStyle({
                fillColor: fillColor,
                fillOpacity: 0.8,
                color: isLight ? 'rgba(0,0,0,0.05)' : 'rgba(0, 243, 255, 0.1)',
                weight: 0.3
            });
        } else {
            pathLayer.setStyle({
                fillColor: 'rgba(255, 255, 255, 0.02)',
                fillOpacity: 0.8,
                color: isLight ? 'rgba(0,0,0,0.05)' : 'rgba(0, 243, 255, 0.1)',
                weight: 0.3
            });
        }

        pathLayer.on('mouseover', function (this: L.Path) {
            this.setStyle({
                fillColor: 'rgba(0, 243, 255, 0.3)'
            });
            (this.getElement() as HTMLElement).style.cursor = 'pointer';
        });

        pathLayer.on('mouseout', function (this: L.Path) {
            const countryData = findCountry(feature.properties);
            if (countryData) {
                this.setStyle({
                    fillColor: colorScale(countryData.count)
                });
            } else {
                this.setStyle({
                    fillColor: 'rgba(255, 255, 255, 0.02)'
                });
            }
        });
    };

    const handleZoomIn = () => {
        if (mapRef.current) {
            mapRef.current.zoomIn();
        }
    };

    const handleZoomOut = () => {
        if (mapRef.current) {
            mapRef.current.zoomOut();
        }
    };

    // Fetch and parse GeoJSON data
    const [geoJsonData, setGeoJsonData] = React.useState<GeoJSONFeatureCollection | null>(null);

    React.useEffect(() => {
        const fetchGeoJson = async () => {
            try {
                const response = await fetch(
                    'https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson'
                );
                const json: GeoJSONFeatureCollection = await response.json();
                setGeoJsonData(json);
            } catch (error) {
                console.error('Error fetching GeoJSON:', error);
            }
        };

        fetchGeoJson();
    }, []);

    const content = (
        <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, minHeight: 0, width: '100%', height: 500 }}>
            {/* Map Column */}
            <Box sx={{ flex: '1 1 65%', position: 'relative', bgcolor: 'rgba(0,0,0,0.3)', height: '100%' }}>
                {/* Zoom Controls Overlay */}
                <Box sx={{ position: 'absolute', top: 10, left: 10, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                    <IconButton
                        size="small"
                        onClick={handleZoomIn}
                        sx={{ bgcolor: 'rgba(5, 5, 20, 0.8)', color: tokens.accent.primary, border: '1px solid rgba(0, 243, 255, 0.2)', borderRadius: 1, p: 0.5, '&:hover': { bgcolor: isLight ? 'rgba(0,0,0,0.05)' : 'rgba(0, 243, 255, 0.1)' } }}
                    >
                        <Plus size={14} />
                    </IconButton>
                    <IconButton
                        size="small"
                        onClick={handleZoomOut}
                        sx={{ bgcolor: 'rgba(5, 5, 20, 0.8)', color: tokens.accent.primary, border: '1px solid rgba(0, 243, 255, 0.2)', borderRadius: 1, p: 0.5, '&:hover': { bgcolor: isLight ? 'rgba(0,0,0,0.05)' : 'rgba(0, 243, 255, 0.1)' } }}
                    >
                        <Box sx={{ width: 14, height: 2, bgcolor: 'currentColor' }} />
                    </IconButton>
                </Box>

                <MapContainer
                    ref={mapRef}
                    center={[5, 15]}
                    zoom={1}
                    minZoom={1}
                    maxZoom={3}
                    style={{ width: '100%', height: '100%' }}
                    zoomControl={false}
                    attributionControl={false}
                    dragging={true}
                    touchZoom={true}
                >
                    <TileLayer
                        url="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png"
                        attribution=""
                    />
                    {geoJsonData && (
                        <GeoJSON data={geoJsonData} onEachFeature={onEachFeature} />
                    )}

                    {/* Markers for Countries with Assets — pulse only top 5 by count */}
                    {(() => {
                        const topIso = new Set(
                            [...data].sort((a, b) => b.count - a.count).slice(0, 5).map((c) => c.iso)
                        );
                        return data.map((country) => {
                        const coords = countryCentroids[country.iso.toUpperCase()];
                        if (!coords) return null;

                        const shouldPulse = topIso.has(country.iso);
                        const customIcon = L.divIcon({
                            className: 'custom-pulsing-marker',
                            html: shouldPulse
                                ? '<div class="map-marker-pulse"></div>'
                                : '<div class="map-marker-pulse map-marker-static"></div>',
                            iconSize: [12, 12],
                            iconAnchor: [6, 6],
                        });

                        return (
                            <Marker
                                key={country.iso}
                                position={coords}
                                icon={customIcon}
                            >
                                <LeafletTooltip
                                    direction="top"
                                    offset={[0, -8]}
                                    opacity={1}
                                    className="tactical-tooltip"
                                >
                                    <Box sx={{ p: 0.5, minWidth: 100 }}>
                                        <Typography variant="caption" sx={{ fontWeight: 800, color: tokens.accent.primary, display: 'block', mb: 0.5, fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron', fontSize: '0.65rem' }}>
                                            {country.name}
                                        </Typography>
                                        <Typography variant="body2" sx={{ fontWeight: 900, color: theme.palette.text.primary, fontSize: '0.75rem', fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron' }}>
                                            {country.count} ASSETS
                                        </Typography>
                                    </Box>
                                </LeafletTooltip>
                            </Marker>
                        );
                        });
                    })()}
                </MapContainer>
            </Box>

            {/* List Column */}
            <Box sx={{ width: { xs: '100%', md: '35%' }, borderLeft: { xs: 'none', md: '1px solid rgba(0, 243, 255, 0.1)' }, borderTop: { xs: '1px solid rgba(0, 243, 255, 0.1)', md: 'none' }, overflow: 'hidden' }}>
                <TableContainer sx={{ flexGrow: 1, overflow: 'auto', width: '100%', '&::-webkit-scrollbar': { width: 4 }, '&::-webkit-scrollbar-thumb': { bgcolor: isLight ? theme.palette.divider : 'rgba(0, 243, 255, 0.2)', borderRadius: 4 } }}>
                    <Table size="small" stickyHeader sx={{ width: '100%' }}>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ bgcolor: isLight ? tokens.bg.secondary : 'rgba(5,5,15,0.98)', borderBottom: `2px solid ${tokens.accent.secondary}`, color: tokens.accent.secondary, fontSize: '0.7rem', fontWeight: 800, fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron', py: 1.5, width: '100%' }}>
                                    COUNTRY
                                </TableCell>
                                <TableCell align="right" sx={{ bgcolor: isLight ? tokens.bg.secondary : 'rgba(5,5,15,0.98)', borderBottom: `2px solid ${tokens.accent.secondary}`, color: tokens.accent.secondary, fontSize: '0.7rem', fontWeight: 800, fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron', py: 1.5 }}>
                                    COUNT
                                </TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {data.length === 0 ? (
                                <TableRow>
                                    <TableCell colSpan={2} align="center" sx={{ py: 4, border: 'none', opacity: 0.5 }}>
                                        <Typography variant="caption" sx={{ letterSpacing: 1 }}>NO_NODES_DETECTED</Typography>
                                    </TableCell>
                                </TableRow>
                            ) : (
                                data.sort((a, b) => b.count - a.count).map((country) => (
                                    <TableRow key={country.iso} sx={{ '&:hover': { bgcolor: isLight ? 'rgba(0,0,0,0.05)' : 'rgba(0, 243, 255, 0.05)' } }}>
                                        <TableCell sx={{ borderBottom: isLight ? '1px solid rgba(0,0,0,0.05)' : '1px solid rgba(255,255,255,0.03)', py: 2 }}>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                                                <Box
                                                    component="img"
                                                    src={`https://flagcdn.com/w20/${country.iso.toLowerCase()}.png`}
                                                    alt={country.name}
                                                    sx={{
                                                        width: 20,
                                                        height: 14,
                                                        borderRadius: '2px',
                                                        border: '1px solid rgba(255,255,255,0.1)',
                                                        boxShadow: '0 0 5px rgba(0,0,0,0.5)'
                                                    }}
                                                />
                                                <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem', color: 'text.primary' }}>
                                                    {country.name}
                                                </Typography>
                                            </Box>
                                        </TableCell>
                                        <TableCell align="right" sx={{ borderBottom: isLight ? '1px solid rgba(0,0,0,0.05)' : '1px solid rgba(255,255,255,0.03)', py: 2 }}>
                                            <Typography sx={{ fontWeight: 800, fontSize: '0.85rem', color: isLight ? theme.palette.text.primary : '#fff', fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron' }}>
                                                {country.count}
                                            </Typography>
                                        </TableCell>
                                    </TableRow>
                                ))
                            )}
                        </TableBody>
                    </Table>
                </TableContainer>
            </Box>
        </Box>
    );

    if (disableCard) {
        return content;
    }

    return (
        <Card sx={{
            height: 500,
            bgcolor: 'rgba(5, 5, 15, 0.6)',
            backdropFilter: 'blur(10px)',
            border: '1px solid rgba(0, 243, 255, 0.1)',
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column'
        }}>
            <CardContent sx={{ p: 0, height: '100%', display: 'flex', flexDirection: 'column' }}>
                <Box sx={{ p: 2, display: 'flex', alignItems: 'center', gap: 1.5, borderBottom: '1px solid rgba(0, 243, 255, 0.1)' }}>
                    <Globe size={20} color="#00f3ff" style={{ filter: 'drop-shadow(0 0 5px #00f3ff)' }} />
                    <Typography variant="h6" sx={{
                        fontSize: '0.85rem',
                        fontWeight: 800,
                        textTransform: 'uppercase',
                        letterSpacing: 2,
                        fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron',
                        color: theme.palette.text.primary
                    }}>
                        Geographical Distribution of Assets
                    </Typography>
                </Box>
                {content}
            </CardContent>
        </Card>
    );
};