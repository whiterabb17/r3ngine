import logging

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from startScan.models import ScanHistory
from reNgine.utils.graph import Neo4jManager
from rest_framework.permissions import IsAuthenticated


from api.serializers import ScanHistorySerializer

logger = logging.getLogger(__name__)


class StressTestingAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            scan = ScanHistory.objects.get(id=id)
        except ScanHistory.DoesNotExist:
            return Response(
                {"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND
            )

        neo4j = Neo4jManager()
        data = neo4j.get_stress_telemetry(id)
        neo4j.close()

        return Response({"status": True, "results": data}, status=status.HTTP_200_OK)


class StressTestingHistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        neo4j = Neo4jManager()
        query = "MATCH (st:StressTest) RETURN DISTINCT st.scan_id as scan_id"
        scan_ids = []
        try:
            with neo4j.driver.session() as session:
                result = session.run(query)
                for record in result:
                    scan_ids.append(record["scan_id"])
        except Exception:
            # Neo4j down: fall back to an empty history instead of a 500.
            logger.warning("Could not read stress test history from Neo4j", exc_info=True)
        neo4j.close()
        
        scans = ScanHistory.objects.filter(id__in=scan_ids).order_by('-id')
        serializer = ScanHistorySerializer(scans, many=True)
        return Response({"status": True, "scans": serializer.data}, status=status.HTTP_200_OK)
