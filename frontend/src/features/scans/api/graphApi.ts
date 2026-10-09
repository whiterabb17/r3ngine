import { useSuspenseQuery, useQuery, useMutation } from '@tanstack/react-query';
import axios from 'axios';
import type { NodeData } from '../../../store/useGraphStore';

/**
 * Cytoscape node served by `/<slug>/api/graph/{scan,target}/<id>/data/`
 * (`Neo4jManager._fetch_graph_data`). `parent` is only set client-side for compound nodes.
 */
export interface GraphNodeElement {
  data: NodeData & { parent?: string };
}

/** Cytoscape edge; `label` is the Neo4j relationship type (e.g. `HAS_SUBDOMAIN`). */
export interface GraphEdgeElement {
  data: {
    source: string;
    target: string;
    label: string;
    scan_ids: number[];
  };
}

export interface GraphData {
  nodes: GraphNodeElement[];
  edges: GraphEdgeElement[];
}

export const useGraphData = (projectSlug: string, scanId?: number, targetId?: number) => {
  return useSuspenseQuery<GraphData>({
    queryKey: ['graph-data', projectSlug, scanId, targetId],
    queryFn: async () => {
      let apiUrl = `/${projectSlug}/api/graph/scan/${scanId}/data/`;
      if (targetId && (!scanId || scanId === 0)) {
        apiUrl = `/${projectSlug}/api/graph/target/${targetId}/data/`;
      }
      const response = await fetch(apiUrl, { credentials: 'include' });
      if (!response.ok) {
        throw new Error('Failed to fetch graph data');
      }
      return response.json();
    }
  });
};

export const useGraphNodeDetails = (projectSlug: string, nodeId: string | null) => {
  return useQuery({
    queryKey: ['graph-node-details', projectSlug, nodeId],
    queryFn: async () => {
      const response = await fetch(`/${projectSlug}/api/graph/node/${nodeId}/details/`, { credentials: 'include' });
      if (!response.ok) {
        throw new Error('Failed to fetch node details');
      }
      return response.json();
    },
    enabled: !!nodeId,
  });
};

/** Downstream subgraph of a node (`Neo4jManager.get_blast_radius`, same shape as the graph data). */
export const useGraphBlastRadius = (projectSlug: string, nodeId: string | null) => {
  return useQuery<GraphData>({
    queryKey: ['graph-blast-radius', projectSlug, nodeId],
    queryFn: async () => {
      const response = await fetch(`/${projectSlug}/api/graph/blast-radius/${nodeId}/`, { credentials: 'include' });
      if (!response.ok) {
        throw new Error('Failed to fetch blast radius');
      }
      return response.json();
    },
    enabled: !!nodeId,
  });
};

export const useCreateTicket = (projectSlug: string) => {
  return useMutation({
    mutationFn: async (nodeId: string) => {
      const response = await axios.post(`/${projectSlug}/api/graph/node/${nodeId}/ticket/`);
      return response.data;
    }
  });
};
