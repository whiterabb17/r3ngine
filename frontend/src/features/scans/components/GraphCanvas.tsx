import React, { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
// @ts-ignore
import fcose from 'cytoscape-fcose';
// @ts-ignore
import klay from 'cytoscape-klay';
// @ts-ignore
import expandCollapse from 'cytoscape-expand-collapse';
// @ts-ignore
import contextMenus from 'cytoscape-context-menus';
import 'cytoscape-context-menus/cytoscape-context-menus.css';

import type { GraphData } from '../api/graphApi';
import { useGraphStore } from '../../../store/useGraphStore';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getChartSeriesColors } from '../../../theme/semanticColors';

cytoscape.use(fcose);
cytoscape.use(klay);
cytoscape.use(expandCollapse);
cytoscape.use(contextMenus);

interface GraphCanvasProps {
  data: GraphData;
  layoutName: 'fcose' | 'klay' | 'cose';
  searchQuery: string;
  onInit?: (cy: cytoscape.Core) => void;
}

export const GraphCanvas: React.FC<GraphCanvasProps> = ({ data, layoutName, searchQuery, onInit }) => {
  const { tokens } = useThemeTokens();
  const scanColors = getChartSeriesColors(tokens);
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const { setSelectedNode } = useGraphStore();

  useEffect(() => {
    if (!containerRef.current) return;

    // Process data to add compound node structures (parent relationships)
    const parentMap = new Map<string, string>();
    data.edges.forEach(edge => {
      const { source, target, label } = edge.data;
      if (['HAS_SUBDOMAIN', 'HAS_ENDPOINT'].includes(label)) {
        if (!parentMap.has(target)) {
           parentMap.set(target, source);
        }
      }
    });

    const processedNodes = data.nodes.map(node => {
      const parentId = parentMap.get(node.data.id);
      return parentId ? { ...node, data: { ...node.data, parent: parentId } } : node;
    });

    const uniqueScans = new Set<number>();
    processedNodes.forEach((n: any) => {
        if (n.data?.scan_ids && Array.isArray(n.data.scan_ids)) {
            n.data.scan_ids.forEach((id: number) => uniqueScans.add(id));
        }
    });
    
    const colorMap: Record<number, string> = {};
    Array.from(uniqueScans).forEach((id, index) => {
        colorMap[id] = scanColors[index % scanColors.length];
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements: {
        nodes: processedNodes,
        edges: data.edges
      },
      boxSelectionEnabled: false,
      autounselectify: true,
      hideEdgesOnViewport: true,
      textureOnViewport: true,
      pixelRatio: 'auto',
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'background-color': 'data(color)',
            'color': tokens.text.primary,
            'font-size': '10px',
            'font-family': 'Inter, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': 5,
            'text-opacity': 0,
            'width': (ele: any) => Math.min(80, 30 + (ele.data('degree_centrality') || 0) * 5),
            'height': (ele: any) => Math.min(80, 30 + (ele.data('degree_centrality') || 0) * 5),
            'border-width': (ele: any) => (ele.data('criticalVulnCount') || 0) > 0 ? 4 : 1,
            'border-color': (ele: any) => (ele.data('criticalVulnCount') || 0) > 0 ? tokens.accent.error : tokens.border.subtle,
            'overlay-padding': 6,
            'z-index': 1,
            'shadow-blur': 10,
            'shadow-color': 'data(color)',
            'shadow-opacity': 0.2
          } as any
        },
        {
          selector: 'node:parent',
          style: {
            'background-opacity': 0.03,
            'background-color': tokens.accent.primary,
            'border-width': 1,
            'border-style': 'solid',
            'border-color': `${tokens.accent.primary}33`,
            'padding': 30,
            'text-valign': 'top',
            'text-margin-y': -10,
            'font-size': '12px',
            'font-weight': 'bold',
            'text-opacity': 0.6,
            'text-transform': 'uppercase',
            'shape': 'roundrectangle',
            'corner-radius': 12
          } as any
        },
        {
          selector: 'node[type = "Domain"]',
          style: {
            'width': 70,
            'height': 70,
            'font-size': '14px',
            'font-weight': 'bold',
            'text-opacity': 1,
            'shape': 'hexagon',
            'border-width': 3,
            'border-color': tokens.border.strong,
            'shadow-opacity': 0.8,
            'shadow-blur': 20
          } as any
        },
        {
          selector: 'node[type = "Vulnerability"]',
          style: {
            'shape': 'diamond',
            'width': 45,
            'height': 45,
            'background-color': tokens.accent.error,
            'shadow-color': tokens.accent.error
          } as any
        },
        {
          selector: 'node.cy-expand-collapse-collapsed-node',
          style: {
            'background-color': tokens.surface.elevated,
            'background-opacity': 0.9,
            'border-width': 2,
            'border-color': tokens.accent.primary,
            'shape': 'roundrectangle',
            'text-opacity': 1,
            'color': tokens.text.primary,
            'label': (ele: any) => `${ele.data('label')} (${ele.data('collapsedChildren')?.length || 0})`
          } as any
        },
        {
          selector: 'edge',
          style: {
            'width': 1,
            'line-color': tokens.border.subtle,
            'target-arrow-color': tokens.border.subtle,
            'target-arrow-shape': 'triangle',
            'curve-style': 'unbundled-bezier',
            'control-point-distances': [20, -20],
            'control-point-weights': [0.25, 0.75],
            'opacity': 0.3
          } as any
        },
        {
            selector: 'node.hover',
            style: {
                'text-opacity': 1,
                'border-width': 4,
                'border-color': tokens.border.strong,
                'z-index': 999,
                'text-background-opacity': 0.9,
                'text-background-color': tokens.surface.elevated,
                'text-background-padding': 4,
                'text-background-shape': 'roundrectangle',
                'shadow-opacity': 1,
                'shadow-blur': 30
            } as any
        },
        {
            selector: 'node.highlighted',
            style: { 'opacity': 1, 'z-index': 100, 'shadow-opacity': 0.6 } as any
        },
        {
            selector: 'node.faded',
            style: { 'opacity': 0.05, 'text-opacity': 0 }
        },
        {
            selector: 'edge.highlighted',
            style: { 'line-color': tokens.accent.primary, 'target-arrow-color': tokens.accent.primary, 'width': 2, 'opacity': 1, 'z-index': 50 } as any
        },
        {
            selector: 'edge.faded',
            style: { 'opacity': 0.02 }
        }
      ]
    });

    // Initialize expand-collapse API
    const expandCollapseApi = (cy as any).expandCollapse({
      layoutBy: {
        name: layoutName,
        animate: true,
        randomize: false,
        fit: true
      },
      fisheye: true,
      animate: true,
      undoable: false,
      expandCollapseCuePosition: 'top-left',
      expandCollapseCueSize: 16,
      expandCollapseCueLineSize: 10,
      expandCueImage: `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${tokens.accent.primary.replace('#', '%23')}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>`,
      collapseCueImage: `data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${tokens.accent.primary.replace('#', '%23')}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="8" y1="12" x2="16" y2="12"></line></svg>`
    });

    // Initialize Context Menus
    (cy as any).contextMenus({
      menuItems: [
        {
          id: 'view-details',
          content: 'View Intelligence Details',
          selector: 'node',
          onClickFunction: (event: any) => {
            const node = event.target;
            setSelectedNode(node.id(), node.data());
          }
        },
        {
          id: 'blast-radius',
          content: 'Calculate Blast Radius',
          selector: 'node',
          onClickFunction: (event: any) => {
             // Logic to switch panel to blast radius
             const node = event.target;
             useGraphStore.getState().setActivePanel('blastRadius');
             setSelectedNode(node.id(), node.data());
          },
          hasTrailingDivider: true
        },
        {
          id: 'run-scan',
          content: 'Initiate Targeted Scan',
          selector: 'node[type="Subdomain"]',
          onClickFunction: (event: any) => {
            alert(`Initiating scan for ${event.target.data('label')}...`);
          }
        }
      ],
      menuItemClasses: ['custom-context-menu-item'],
      contextMenuClasses: ['custom-context-menu']
    });

    // Initial Layout
    cy.layout({ 
      name: layoutName,
      animate: true,
      nodeDimensionsIncludeLabels: true,
      ...(layoutName === 'fcose' ? {
        quality: 'default',
        randomize: true,
        nodeRepulsion: 4500,
        idealEdgeLength: 100,
        edgeElasticity: 0.45,
        nestingFactor: 0.1,
        gravity: 0.25,
        numIter: 2500,
      } : layoutName === 'klay' ? {
        klay: {
          direction: 'DOWN',
          spacing: 50,
          nodeLayering: 'NETWORK_SIMPLEX'
        }
      } : {})
    } as any).run();

    cy.on('mouseover', 'node', (e) => {
        const node = e.target;
        const neighborhood = node.neighborhood().add(node);
        cy.elements().addClass('faded');
        neighborhood.removeClass('faded').addClass('highlighted');
        node.addClass('hover');
    });

    cy.on('mouseout', 'node', () => {
        cy.elements().removeClass('faded highlighted hover');
    });

    cy.on('tap', 'node', (e) => {
        const node = e.target;
        setSelectedNode(node.id(), node.data());
    });

    cy.on('tap', (e) => {
        if (e.target === cy) {
            setSelectedNode(null);
        }
    });

    cyRef.current = cy;
    if (onInit) onInit(cy);

    return () => {
      cy.destroy();
    };
  }, [data]);

  // Handle Search and Layout changes without re-initializing
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    if (searchQuery) {
      const matches = cy.nodes().filter((node: any) => 
        node.data('label')?.toLowerCase().includes(searchQuery.toLowerCase())
      );

      if (matches.length > 0) {
        cy.elements().addClass('faded');
        matches.removeClass('faded').addClass('highlighted');
        if (matches.length === 1) {
          cy.animate({ center: { eles: matches }, zoom: 1.5, duration: 500 });
        }
      } else {
        cy.elements().addClass('faded');
      }
    } else {
      cy.elements().removeClass('faded highlighted hover');
    }
  }, [searchQuery]);

  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.layout({ 
      name: layoutName,
      animate: true,
      ...(layoutName === 'fcose' ? {
        nodeRepulsion: 4500,
        idealEdgeLength: 100,
      } : layoutName === 'klay' ? {
        klay: { direction: 'DOWN', spacing: 50 }
      } : {})
    } as any).run();
  }, [layoutName]);

  return <div ref={containerRef} style={{ width: '100%', height: '100%' }} />;
};
