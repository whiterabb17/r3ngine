"""
Full Chain Graph REST API views.

Provides read-only Neo4j queries for the expanded attack-chain graph.
All node_type values are validated against an allowlist (Security Rule 5.1).
scan_id is always an integer parameter — never interpolated (Security Rule 5.1).
"""

import logging
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

logger = logging.getLogger(__name__)

_ALLOWED_NODE_TYPES = frozenset([
    "Organization", "Subdomain", "IPAddress", "Application",
    "Technology", "Certificate", "IdentityInfra", "APIEndpoint",
    "APMENode", "Vulnerability", "CVE",
])


class FullChainGraphView(APIView):
    """
    GET /api/graph/chain/?scan_id=<id>

    Returns nodes and edges for the full attack chain graph in a scan.
    Neo4j is queried only if scan_id is a valid integer tied to an existing scan.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scan_id = request.query_params.get("scan_id")
        if not scan_id:
            return Response({"error": "scan_id required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            scan_id = int(scan_id)
        except (ValueError, TypeError):
            return Response(
                {"error": "scan_id must be integer"}, status=status.HTTP_400_BAD_REQUEST
            )

        from startScan.models import ScanHistory
        if not ScanHistory.objects.filter(id=scan_id).exists():
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            from reNgine.utils.graph import Neo4jManager
            mgr = Neo4jManager()
            graph = mgr.get_full_chain_graph(scan_id)
        except Exception as exc:
            logger.error(
                "graph_intel: full_chain query failed scan_id=%s: %s", scan_id, exc
            )
            return Response(
                {"error": "Graph query failed"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(graph)


class ChainNodesByTypeView(APIView):
    """
    GET /api/graph/chain/nodes/?scan_id=<id>&type=<NodeType>

    Returns all nodes of a specific type for a scan.
    `type` is validated against the allowlist — returns 400 for invalid types.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scan_id = request.query_params.get("scan_id")
        node_type = request.query_params.get("type")

        if not scan_id:
            return Response({"error": "scan_id required"}, status=status.HTTP_400_BAD_REQUEST)
        if not node_type:
            return Response({"error": "type required"}, status=status.HTTP_400_BAD_REQUEST)

        if node_type not in _ALLOWED_NODE_TYPES:
            return Response(
                {"error": f"type must be one of: {sorted(_ALLOWED_NODE_TYPES)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            scan_id = int(scan_id)
        except (ValueError, TypeError):
            return Response(
                {"error": "scan_id must be integer"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from reNgine.utils.graph import Neo4jManager
            mgr = Neo4jManager()
            nodes = mgr.get_chain_nodes_by_type(scan_id, node_type)
        except Exception as exc:
            logger.error(
                "graph_intel: nodes_by_type failed scan_id=%s type=%s: %s",
                scan_id, node_type, exc,
            )
            return Response(
                {"error": "Graph query failed"}, status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response({"type": node_type, "count": len(nodes), "nodes": nodes})
