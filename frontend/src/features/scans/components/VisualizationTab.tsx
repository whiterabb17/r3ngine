import React, { useEffect, useRef, useState } from 'react';
import { Box, CircularProgress, Typography, Switch, FormControlLabel, IconButton, Tooltip, Paper } from '@mui/material';
import { Download, Maximize2, RefreshCw } from 'lucide-react';
import * as d3 from 'd3';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { fetchScanVisualisation, type ScanVisualisationNode } from '../api/scanResults';

/**
 * A laid-out tree node with the collapsible-tree bookkeeping d3 leaves to the caller:
 * `_children` holds hidden children, `x0`/`y0` the previous position for transitions.
 */
type VizNode = d3.HierarchyPointNode<ScanVisualisationNode> & {
  _children?: VizNode[];
  x0?: number;
  y0?: number;
  /** Stable data-join key; d3's own `id` is read-only. */
  vizId?: number;
};

interface VizLink {
  source: VizNode;
  target: VizNode;
}

interface VisualizationTabProps {
  projectSlug: string;
  scanId?: number;
  targetId?: number;
}

const VisualizationTab: React.FC<VisualizationTabProps> = ({ scanId, targetId }) => {
  const { tokens } = useThemeTokens();
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandAll, setExpandAll] = useState(false);
  const [data, setData] = useState<ScanVisualisationNode | null>(null);

  useEffect(() => {
    fetchData();
  }, [scanId, targetId]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const trees = await fetchScanVisualisation({ scanId, targetId });
      if (trees && trees.length > 0) {
        setData(trees[0]);
      } else {
        setError('No visualization data found.');
      }
    } catch (err) {
      console.error('Error fetching visualization data:', err);
      setError('Failed to load visualization data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!data || !svgRef.current) return;

    renderChart(data);
  }, [data, expandAll]);

  const renderChart = (treeData: ScanVisualisationNode) => {
    const svgElement = svgRef.current;
    if (!svgElement) return;

    const width = containerRef.current?.clientWidth || 1200;
    const height = 800;
    const margin = { top: 20, right: 120, bottom: 20, left: 120 };

    // Clear previous SVG content
    const svg = d3.select(svgElement);
    svg.selectAll("*").remove();

    const g = svg.append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    // Zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 3])
      .on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
        g.attr("transform", event.transform.toString());
      });

    svg.call(zoom);

    const tree = d3.tree<ScanVisualisationNode>()
      .nodeSize([30, 200]); // [height, width] per node

    // The tree layout assigns x/y in place on every update() below, before any position is read.
    const root = d3.hierarchy<ScanVisualisationNode>(treeData) as VizNode;

    // Initial expansion/collapse
    if (!expandAll) {
      root.descendants().forEach((d) => {
        if (d.depth > 1) {
          d._children = d.children;
          d.children = undefined;
        }
      });
    }

    let i = 0;
    const duration = 750;

    const update = (source: VizNode) => {
      const nodes = root.descendants().reverse();
      // links() is typed with plain point nodes, but it returns the same objects as descendants().
      const links = root.links() as VizLink[];
      // Where entering elements start and exiting ones collapse to, as [y, x] for a horizontal tree.
      const enterOrigin: [number, number] = [source.y0 ?? 0, source.x0 ?? 0];

      tree(root);

      let left = root;
      let right = root;
      root.eachBefore(node => {
        if (node.x < left.x) left = node;
        if (node.x > right.x) right = node;
      });

      const height = right.x - left.x + margin.top + margin.bottom;

      // Typed as BaseType so the node and link selections can inherit its timing via .transition(t).
      const transition = d3.select<d3.BaseType, unknown>(svgElement).transition()
        .duration(duration)
        .attr("viewBox", [-margin.left, left.x - margin.top, width, height].join(","));
      if (typeof window.ResizeObserver === 'undefined') {
        transition.tween("resize", () => () => {
          svg.dispatch("toggle");
        });
      }

      // Update nodes
      const node = g.selectAll<SVGGElement, VizNode>("g.node")
        .data(nodes, (d) => d.vizId || (d.vizId = ++i));

      const nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .attr("transform", () => `translate(${source.y0},${source.x0})`)
        .attr("fill-opacity", 0)
        .attr("stroke-opacity", 0)
        .on("click", (_event: MouseEvent, d) => {
          if (d.children) {
            d._children = d.children;
            d.children = undefined;
          } else {
            d.children = d._children;
            d._children = undefined;
          }
          update(d);
        });

      nodeEnter.append("circle")
        .attr("r", 6)
        .attr("fill", (d) => d._children ? tokens.accent.primary : "rgba(255,255,255,0.2)")
        .attr("stroke", tokens.accent.primary)
        .attr("stroke-width", 1.5)
        .style("cursor", "pointer");

      nodeEnter.append("text")
        .attr("dy", "0.31em")
        .attr("x", (d) => d._children || d.children ? -10 : 10)
        .attr("text-anchor", (d) => d._children || d.children ? "end" : "start")
        .attr("fill", (d) => {
          const nodeData = d.data;
          if ((nodeData.http_status ?? 0) >= 400 || nodeData.title === 'Interesting') return "#ff003c";
          if (nodeData.http_status === 200) return "#00ff62";
          return "rgba(255,255,255,0.8)";
        })
        .attr("font-family", "Orbitron, sans-serif")
        .attr("font-size", "0.7rem")
        .text((d) => (d.data.title === 'Interesting' ? `(★) ${d.data.description}` : d.data.description))
        .clone(true).lower()
        .attr("stroke-linejoin", "round")
        .attr("stroke-width", 3)
        .attr("stroke", "rgba(10,10,15,0.8)");

      const nodeUpdate = node.merge(nodeEnter).transition(transition)
        .attr("transform", d => `translate(${d.y},${d.x})`)
        .attr("fill-opacity", 1)
        .attr("stroke-opacity", 1);

      nodeUpdate.select("circle")
        .attr("fill", (d) => d._children ? tokens.accent.primary : "rgba(10,10,15,0.8)");

      node.exit<VizNode>().transition(transition).remove()
        .attr("transform", () => `translate(${source.y},${source.x})`)
        .attr("fill-opacity", 0)
        .attr("stroke-opacity", 0);

      // Update links
      const link = g.selectAll<SVGPathElement, VizLink>("path.link")
        .data(links, (d) => d.target.vizId ?? '');

      const linkEnter = link.enter().append("path")
        .attr("class", "link")
        .attr("d", () => d3.linkHorizontal()({ source: enterOrigin, target: enterOrigin }))
        .attr("fill", "none")
        .attr("stroke", "rgba(0,243,255,0.15)")
        .attr("stroke-width", 1.5);

      link.merge(linkEnter).transition(transition)
        .attr("d", d3.linkHorizontal<VizLink, VizNode>()
          .x((d) => d.y)
          .y((d) => d.x)
        );

      link.exit<VizLink>().transition(transition).remove()
        .attr("d", () => {
          const exitTarget: [number, number] = [source.y, source.x];
          return d3.linkHorizontal()({ source: exitTarget, target: exitTarget });
        });

      // Stash the old positions for transition
      root.eachBefore(d => {
        d.x0 = d.x;
        d.y0 = d.y;
      });
    };

    root.x0 = height / 2;
    root.y0 = 0;

    update(root);
  };

  const handleDownload = () => {
    if (!svgRef.current) return;
    const svgData = new XMLSerializer().serializeToString(svgRef.current);
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    const img = new Image();
    img.onload = () => {
      canvas.width = img.width * 2;
      canvas.height = img.height * 2;
      ctx?.drawImage(img, 0, 0, canvas.width, canvas.height);
      const pngFile = canvas.toDataURL("image/png");
      const downloadLink = document.createElement("a");
      downloadLink.download = `visualization_${scanId}.png`;
      downloadLink.href = pngFile;
      downloadLink.click();
    };
    img.src = "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svgData)));
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px' }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography color="error">{error}</Typography>
        <IconButton onClick={fetchData} sx={{ mt: 2, color: tokens.accent.primary }}>
          <RefreshCw size={20} />
        </IconButton>
      </Box>
    );
  }

  return (
    <TacticalPanel 
      title="SCAN RESULT VISUALIZATION" 
      icon={<Maximize2 size={14} />}
      headerAction={
        <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: { xs: 1, sm: 2 }, justifyContent: 'flex-end' }}>
          <FormControlLabel
            sx={{ m: 0 }}
            control={
              <Switch 
                checked={expandAll} 
                onChange={(e) => setExpandAll(e.target.checked)}
                size="small"
                sx={{ 
                  '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                  '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary }
                }}
              />
            }
            label={<Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 900, fontFamily: 'Orbitron' }}>EXPAND ALL</Typography>}
          />
          <Tooltip title="Download as PNG">
            <IconButton size="small" onClick={handleDownload} sx={{ color: tokens.accent.primary }}>
              <Download size={16} />
            </IconButton>
          </Tooltip>
        </Box>
      }
    >
      <Box ref={containerRef} sx={{ position: 'relative', overflow: 'hidden', bgcolor: 'rgba(10,10,15,0.3)', borderRadius: 1, minHeight: '700px' }}>
        <svg 
          ref={svgRef} 
          width="100%" 
          height="800" 
          style={{ cursor: 'grab' }}
        />
        
        {/* Legend */}
        <Paper 
          sx={{ 
            position: 'absolute', 
            bottom: 20, 
            right: 20, 
            p: 1.5, 
            bgcolor: 'rgba(10,10,15,0.9)', 
            border: `1px solid ${tokens.accent.primary}33`,
            backdropFilter: 'blur(10px)'
          }}
        >
          <Typography sx={{ fontSize: '0.6rem', color: tokens.accent.primary, fontWeight: 900, mb: 1, fontFamily: 'Orbitron' }}>LEGEND</Typography>
          <Stack spacing={0.5}>
            <LegendItem color="#00ff62" label="200 OK / SAFE" />
            <LegendItem color="#ff003c" label="40x / INTERESTING / CRITICAL" />
            <LegendItem color="rgba(255,255,255,0.8)" label="OTHER" />
          </Stack>
        </Paper>
      </Box>
    </TacticalPanel>
  );
};

const LegendItem = ({ color, label }: { color: string, label: string }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
    <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: color, boxShadow: `0 0 5px ${color}` }} />
    <Typography sx={{ fontSize: '0.55rem', color: 'rgba(255,255,255,0.6)', fontWeight: 700 }}>{label}</Typography>
  </Box>
);

const Stack = ({ children, spacing }: { children: React.ReactNode, spacing: number }) => (
  <Box sx={{ display: 'flex', flexDirection: 'column', gap: spacing }}>{children}</Box>
);

export default VisualizationTab;
