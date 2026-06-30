import { useQuery } from '@tanstack/react-query';

export interface ChainGraphNode {
  id: string;
  type: string;
  color: string;
  properties: Record<string, unknown>;
}

export interface ChainGraphEdge {
  from: string | null;
  to: string;
  type: string;
}

export interface ChainGraphResponse {
  nodes: ChainGraphNode[];
  edges: ChainGraphEdge[];
}

export interface ChainNodesByTypeResponse {
  type: string;
  count: number;
  nodes: Array<Record<string, unknown>>;
}

async function fetchFullChainGraph(scanId: number): Promise<ChainGraphResponse> {
  const resp = await fetch(`/api/graph/chain/?scan_id=${scanId}`, {
    headers: { 'Content-Type': 'application/json' },
  });
  if (!resp.ok) {
    throw new Error(`Full chain graph fetch failed: ${resp.status}`);
  }
  return resp.json();
}

async function fetchChainNodesByType(
  scanId: number,
  nodeType: string
): Promise<ChainNodesByTypeResponse> {
  const resp = await fetch(
    `/api/graph/chain/nodes/?scan_id=${scanId}&type=${encodeURIComponent(nodeType)}`,
    { headers: { 'Content-Type': 'application/json' } }
  );
  if (!resp.ok) {
    throw new Error(`Chain nodes fetch failed: ${resp.status}`);
  }
  return resp.json();
}

export const useFullChainGraph = (scanId: number | undefined) =>
  useQuery<ChainGraphResponse>({
    queryKey: ['full-chain-graph', scanId],
    queryFn: () => fetchFullChainGraph(scanId!),
    enabled: scanId !== undefined,
    staleTime: 60_000,
  });

export const useChainNodesByType = (
  scanId: number | undefined,
  nodeType: string | undefined
) =>
  useQuery<ChainNodesByTypeResponse>({
    queryKey: ['chain-nodes-by-type', scanId, nodeType],
    queryFn: () => fetchChainNodesByType(scanId!, nodeType!),
    enabled: scanId !== undefined && nodeType !== undefined,
  });
