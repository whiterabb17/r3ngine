import logging
import json
from typing import Any, Dict, List, Optional

from apme.models.path import AttackPath, PathStep
from reNgine.llm import LLMBaseGenerator
from reNgine.privacy import PIIGate
from startScan.models import ScanHistory, Subdomain, Vulnerability, EndPoint, ImpactAssessment

logger = logging.getLogger(__name__)

class LLMPathOrchestrator:
    """
    On-demand Attack Path Modeling using the configured LLM.
    Gathers scan context, masks PII, prompts the LLM, and persists findings.
    """

    def __init__(self):
        """
        Initialize the LLMPathOrchestrator class.
        Sets up the LLMBaseGenerator for API interactions and PIIGate for privacy validation.
        """
        self.generator = LLMBaseGenerator(logger)
        self.gate = PIIGate()

    def run(self, scan_history_id: int) -> Dict[str, Any]:
        """
        Execute the LLM-assisted modeling pipeline.

        Args:
            scan_history_id (int): The database ID of the ScanHistory to analyze.

        Returns:
            Dict[str, Any]: A dictionary containing total paths found, details of each path, or an error message.
        """
        logger.info(f"LLM APME: Starting for scan_history_id={scan_history_id}")
        
        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
        except ScanHistory.DoesNotExist:
            logger.error(f"LLM APME: Scan {scan_history_id} not found.")
            return {"error": "Scan not found"}

        # 1. Gather Context
        context = self._gather_context(scan)
        if not context.get('vulnerabilities') and not context.get('subdomains'):
            return {"total_paths": 0, "paths": [], "message": "No data to analyze"}

        # 2. Prompt LLM
        llm_response = self._get_llm_paths(context)
        if not llm_response:
            return {"error": "Failed to get response from LLM"}

        # 3. Parse and Persist
        paths = self._parse_and_save_paths(llm_response, scan)
        
        return {
            "total_paths": len(paths),
            "paths": [p.to_dict() for p in paths]
        }

    def _gather_context(self, scan: ScanHistory) -> Dict[str, Any]:
        """Gather scan findings for the prompt.

        Args:
            scan (ScanHistory): The ScanHistory instance to retrieve findings for.

        Returns:
            Dict[str, Any]: A dictionary containing gathered subdomains, vulnerabilities, endpoints, and root domain.
        """
        domain_id = scan.domain_id
        
        # Fetch Subdomains
        subdomains = Subdomain.objects.filter(
            target_domain_id=domain_id
        ).prefetch_related("ip_addresses", "ip_addresses__ports", "technologies")
        sub_list = []
        for s in subdomains:
            ips = s.ip_addresses.all()
            ports = []
            for ip in ips:
                for port in ip.ports.all():
                    ports.append(f"{port.number}/{port.service_name}")
            sub_list.append({
                "name": s.name,
                "ip": ", ".join(ip.address for ip in ips),
                "ports": ", ".join(ports),
                "technologies": [t.name for t in s.technologies.all()]
            })

        # Fetch Vulnerabilities
        vulnerabilities = Vulnerability.objects.filter(scan_history=scan)
        vuln_list = []
        for v in vulnerabilities:
            vuln_list.append({
                "id": v.id,
                "title": v.name,
                "severity": v.severity,
                "description": v.description,
                "subdomain": v.subdomain.name if v.subdomain else "unknown"
            })

        # Fetch Endpoints
        endpoints = EndPoint.objects.filter(scan_history=scan)[:50] # Limit to avoid token overflow
        ep_list = []
        for e in endpoints:
            ep_list.append({
                "url": e.http_url,
                "status": e.http_status,
                "title": e.page_title
            })

        return {
            "subdomains": sub_list,
            "vulnerabilities": vuln_list,
            "endpoints": ep_list,
            "domain": scan.domain.name
        }

    def _get_llm_paths(self, context: Dict[str, Any]) -> Optional[str]:
        """Send context to LLM and get modeled paths.

        Args:
            context (Dict[str, Any]): The reconnaissance and scan findings context dictionary.

        Returns:
            Optional[str]: The raw text/JSON response from the LLM, or None if the request failed.
        """
        system_prompt = """
        You are an elite Red Team Architect and Attack Path Analyst. 
        Your goal is to identify logical and high-risk attack paths based on the provided reconnaissance data and vulnerabilities.

        OBJECTIVE:
        Model the most plausible attack chains that a sophisticated adversary would take to achieve full system compromise, data exfiltration, or lateral movement.

        INPUT DATA:
        - Subdomains and their associated IPs/Ports/Tech.
        - Identified Vulnerabilities (with severity and descriptions).
        - Discovered Endpoints.

        OUTPUT REQUIREMENTS:
        Return a valid JSON object containing an array of 'paths'.
        Each path must have:
        - 'path_id': A unique short identifier (e.g., AP-01).
        - 'risk': One of [critical, high, medium, low].
        - 'score': A numeric value from 0.0 to 10.0.
        - 'potential_impact': A brief summary of what is achieved at the end of the path.
        - 'steps': An array of objects:
            - 'from': The starting node label (e.g., 'internet', or a subdomain name).
            - 'to': The destination node label (e.g., a subdomain, a specific service, or 'Internal Data').
            - 'action': The exploit or action taken (e.g., 'SQL Injection', 'Brute Force', 'Lateral Movement').
            - 'confidence': 0.0 to 1.0.
            - 'edge_type': Descriptive type (e.g., 'exploit', 'discovery', 'access').

        CRITICAL CONSTRAINTS:
        1. Only return VALID JSON. No extra text.
        2. Use the provided subdomain names and vulnerability titles where applicable.
        3. Be realistic. If no critical vulnerabilities exist, do not invent them.
        4. Focus on multi-step chains (e.g., Gain access via X -> Discover internal Y -> Exploit Z).
        """

        user_message = f"Reconnaissance Context for {context['domain']}:\n{json.dumps(context, indent=2)}"
        
        # LLMBaseGenerator handles anonymization via PIIGate
        return self.generator._call_llm(system_prompt, user_message)

    def _parse_and_save_paths(self, llm_output: str, scan: ScanHistory) -> List[AttackPath]:
        """Parse LLM JSON response and save to database.

        Args:
            llm_output (str): The raw text response from the LLM.
            scan (ScanHistory): The ScanHistory database object to associate findings with.

        Returns:
            List[AttackPath]: A list of parsed AttackPath data-class instances.
        """
        try:
            # Clean possible markdown noise
            json_str = llm_output.strip()
            if json_str.startswith('```json'):
                json_str = json_str[7:-3].strip()
            elif json_str.startswith('```'):
                json_str = json_str[3:-3].strip()

            data = json.loads(json_str)
            raw_paths = data.get('paths', [])
            
            parsed_paths = []
            for rp in raw_paths:
                steps = []
                for rs in rp.get('steps', []):
                    steps.append(PathStep(
                        from_id=rs.get('from', ''),
                        to_id=rs.get('to', ''),
                        action=rs.get('action', ''),
                        confidence=rs.get('confidence', 0.5),
                        edge_type=rs.get('edge_type', 'exploit'),
                        validated=False # AI generated paths are inferred by default
                    ))
                
                ap = AttackPath(
                    id=rp.get('path_id', 'AI-PATH'),
                    start=steps[0].from_id if steps else 'internet',
                    end=steps[-1].to_id if steps else 'target',
                    steps=steps,
                    score=rp.get('score', 5.0),
                    risk=rp.get('risk', 'medium')
                )
                parsed_paths.append(ap)

                # Persist to ImpactAssessment
                self._persist_to_db(ap, scan)

            return parsed_paths

        except Exception as e:
            logger.error(f"LLM APME: Failed to parse or save paths: {str(e)}")
            logger.debug(f"Raw Output: {llm_output}")
            return []

    def _persist_to_db(self, path: AttackPath, scan: ScanHistory):
        """Save a single path to ImpactAssessment.

        Args:
            path (AttackPath): The AttackPath instance to save.
            scan (ScanHistory): The ScanHistory database object to link.
        """
        try:
            # Try to find a representative vulnerability in the path to link it
            # We look for steps that mention something that looks like a vuln
            vuln = None
            for step in path.steps:
                # Basic heuristic: if the action matches a vulnerability name in this scan
                v_query = Vulnerability.objects.filter(scan_history=scan, name__icontains=step.action)
                if v_query.exists():
                    vuln = v_query.first()
                    break

            ImpactAssessment.objects.create(
                scan_history=scan,
                vulnerability=vuln,
                is_ai_generated=True,
                potential_attack_chain={
                    "apme_path_id": path.id,
                    "risk": path.risk,
                    "score": path.score,
                    "steps": [s.to_dict() for s in path.steps],
                    "is_llm_generated": True
                },
                potential_impact=f"LLM-Generated Attack Path: {path.id}. Risk: {path.risk.upper()}. End Goal: {path.end}",
                remediation_priority=self._risk_to_priority(path.risk)
            )
        except Exception as e:
            logger.error(f"LLM APME: Database persistence failed: {str(e)}")

    def _risk_to_priority(self, risk: str) -> int:
        """Map a risk severity level string to an integer remediation priority.

        Args:
            risk (str): The risk severity level string (e.g. 'critical', 'high', 'medium', 'low').

        Returns:
            int: The integer representation of the priority (from 1 to 5).
        """
        return {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(risk.lower(), 1)
