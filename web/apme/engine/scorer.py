"""
APME Scoring Engine

Scores attack paths. Additive factors (sum = 1.0):
- Vulnerability severity            (0.15 weight)
- Exploitability / CVSS             (0.15 weight)
- Path length — shorter=higher risk (0.10 weight)
- Privilege gained                  (0.15 weight)
- Impact (blast radius + sensitivity) (0.12 weight)
- EPSS score                        (0.13 weight)
- PoC / exploit availability        (0.08 weight)
- Recency (CVE age)                 (0.04 weight)
- Connectivity (target node degree) (0.05 weight)
- Stealthiness (boundary crossings) (0.03 weight)

Post-sum modifiers (applied after additive sum):
- Path confidence product multiplier  x[0.5, 1.0]
- CISA KEV tiered boost               +0.15 (KEV+PoC) or +0.10 (KEV alone)
- ERL validated step boost            +0.05 per step, max +0.15 (requires >= 2 steps)

Risk classification:
  speculative : 0 validated steps AND score < 0.40
  low         : score <= 0.50
  medium      : score <= 0.70 (or constraint 22: unvalidated + no signal + score >= 0.70)
  high        : score <= 0.85
  critical    : score  > 0.85
"""

import datetime
import logging
from typing import Any, Dict, List

from apme.models.path import AttackPath, PathStep

logger = logging.getLogger(__name__)

SEVERITY_MAP = {-1: 0.0, 0: 0.05, 1: 0.25, 2: 0.50, 3: 0.75, 4: 1.0}
PRIVILEGE_MAP = {"none": 0.0, "user": 0.25, "admin": 0.75, "domain_admin": 1.0, "root": 1.0}

# Edge types that represent boundary crossings (noisy, reduce stealthiness)
_BOUNDARY_EDGE_TYPES = {"CONNECTED_TO", "TRUSTS"}


class Scorer:
    """Computes a risk score for a complete attack path."""

    WEIGHTS = {
        "severity":        0.10,
        "exploitability":  0.10,
        "path_length":     0.10,
        "privilege_gain":  0.10,
        "impact":          0.12,
        "epss":            0.10,
        "poc":             0.05,
        "recency":         0.04,
        "connectivity":    0.04,
        "stealthiness":    0.05,
        "exposure":        0.10,
        "auth_state":      0.10,
    }

    def __init__(self):
        self._blast_radius_cache: Dict[str, int] = {}

    def score(self, path: AttackPath, path_metadata: Dict[str, Any]) -> float:
        """Compute and set path.score and path.risk. Returns the final score."""
        steps = path.steps
        if not steps:
            path.score = 0.0
            path.risk = "low"
            return 0.0

        # 1. Severity
        severity_raw = path_metadata.get("severity", -1)
        severity_score = SEVERITY_MAP.get(severity_raw, 0.0)

        # 2. Exploitability
        cvss = path_metadata.get("cvss_score", 0.0)
        exploitability = min(cvss / 10.0, 1.0) if cvss else severity_score * 0.8

        # 3. Path length (shorter = higher risk)
        length_score = 1.0 / max(len(steps), 1)

        # 4. Privilege gained
        privilege = path_metadata.get("privilege_gained", "none")
        privilege_score = PRIVILEGE_MAP.get(privilege, 0.0)

        # 5. Impact (blast radius + target sensitivity)
        blast_radius = path_metadata.get("blast_radius", 1)
        blast_score = min(blast_radius / 50.0, 1.0)
        sensitivity_val = path_metadata.get("target_sensitivity", "low")
        sensitivity_score = {"high": 1.0, "medium": 0.6, "low": 0.2}.get(sensitivity_val, 0.2)
        impact_score = (blast_score * 0.4) + (sensitivity_score * 0.6)

        # 6. EPSS
        epss_percentile = path_metadata.get("epss_percentile", 0.0)
        epss_score = min(epss_percentile / 100.0, 1.0) if epss_percentile else 0.0

        # 7. PoC / exploit availability
        has_metasploit = path_metadata.get("has_metasploit", False)
        has_exploit_url = path_metadata.get("has_exploit_url", False)
        has_poc = path_metadata.get("has_poc", False)
        if has_metasploit:
            poc_score = 1.0
        elif has_exploit_url:
            poc_score = 0.80
        elif has_poc:
            poc_score = 0.60
        else:
            poc_score = 0.0

        # 8. Recency (CVE age)
        cve_date = path_metadata.get("cve_published_date")
        has_kev = path_metadata.get("has_cisa_kev", False)
        recency_score = self._compute_recency(cve_date, has_kev)

        # 9. Connectivity (target node degree)
        target_degree = path_metadata.get("target_node_degree", 1)
        connectivity_score = min(float(target_degree) / 20.0, 1.0)

        # 10. Stealthiness (boundary crossings + victim-interaction steps)
        boundary_crossings = sum(
            1 for s in steps if s.edge_type in _BOUNDARY_EDGE_TYPES
        )
        victim_steps = sum(
            1 for s in steps
            if "victim" in s.action.lower() or s.edge_type == "REQUIRES_VICTIM"
        )
        stealthiness_score = max(0.0, 1.0 - boundary_crossings * 0.2 - victim_steps * 0.3)

        # 11. Exposure (Internal vs External)
        exposure_val = path_metadata.get("exposure", "external")
        exposure_score = 1.0 if exposure_val == "external" else 0.3

        # 12. Auth State
        auth_val = path_metadata.get("auth_state", "unauthenticated")
        auth_score = 1.0 if auth_val == "unauthenticated" else 0.5

        # Additive sum (weights sum to 1.0)
        score = (
            severity_score      * self.WEIGHTS["severity"]
            + exploitability    * self.WEIGHTS["exploitability"]
            + length_score      * self.WEIGHTS["path_length"]
            + privilege_score   * self.WEIGHTS["privilege_gain"]
            + impact_score      * self.WEIGHTS["impact"]
            + epss_score        * self.WEIGHTS["epss"]
            + poc_score         * self.WEIGHTS["poc"]
            + recency_score     * self.WEIGHTS["recency"]
            + connectivity_score * self.WEIGHTS["connectivity"]
            + stealthiness_score * self.WEIGHTS["stealthiness"]
            + exposure_score     * self.WEIGHTS["exposure"]
            + auth_score         * self.WEIGHTS["auth_state"]
        )

        # Path confidence product multiplier [0.5, 1.0]
        conf_product = path_metadata.get("path_confidence_product", 1.0)
        conf_multiplier = max(min(float(conf_product), 1.0), 0.5)
        score *= conf_multiplier

        # CISA KEV tiered boost
        if has_kev:
            if has_poc or has_exploit_url:
                score = min(score + 0.15, 1.0)
            else:
                score = min(score + 0.10, 1.0)

        # ERL validated step boost (+0.05 per validated step, max +0.15)
        # Requires at least 2 steps in path to apply
        validated = path_metadata.get("validated_steps", 0)
        if validated > 0 and len(steps) >= 2:
            score = min(score + min(validated * 0.05, 0.15), 1.0)

        score = round(score, 4)
        path.score = score
        path.risk = self._classify(score, path, path_metadata)

        logger.debug(
            "APME Scorer: path=%s score=%.4f risk=%s "
            "(sev=%.2f expl=%.2f len=%.2f priv=%.2f impact=%.2f epss=%.2f "
            "poc=%.2f recency=%.2f conn=%.2f stealth=%.2f exp=%.2f auth=%.2f conf_mult=%.2f)",
            path.id, score, path.risk, severity_score, exploitability,
            length_score, privilege_score, impact_score, epss_score,
            poc_score, recency_score, connectivity_score, stealthiness_score,
            exposure_score, auth_score,
            conf_multiplier,
        )
        return score

    @staticmethod
    def _compute_recency(cve_date, has_kev: bool) -> float:
        """Compute recency score from CVE published date.

        Args:
            cve_date (Any): The CVE published date, which can be None, a string, 
                             a datetime.date, or a datetime.datetime object.
            has_kev (bool): Whether the vulnerability is in the CISA KEV list.

        Returns:
            float: The computed recency score (ranging from 0.15 to 1.0).
        """
        if not cve_date:
            return 0.50 if has_kev else 0.15

        # If cve_date is a string, attempt robust parsing to a datetime.date object
        if isinstance(cve_date, str):
            cve_date = cve_date.strip()
            if not cve_date or cve_date.lower() == "none":
                return 0.50 if has_kev else 0.15
            try:
                # Attempt standard ISO format (YYYY-MM-DD)
                cve_date = datetime.date.fromisoformat(cve_date)
            except ValueError:
                try:
                    # Attempt standard datetime string format with space
                    cve_date = datetime.datetime.strptime(cve_date, "%Y-%m-%d %H:%M:%S").date()
                except ValueError:
                    try:
                        # Attempt standard ISO format with 'T' separator
                        cve_date = datetime.datetime.fromisoformat(cve_date).date()
                    except ValueError:
                        # Default fallback if parsing fails completely
                        return 0.50 if has_kev else 0.15

        # Normalize datetime to date if necessary
        if isinstance(cve_date, datetime.datetime):
            cve_date = cve_date.date()

        # Compute age in days and return the corresponding recency score
        if isinstance(cve_date, datetime.date):
            today = datetime.date.today()
            age_days = (today - cve_date).days
            if age_days < 30:
                return 1.0
            if age_days < 180:
                return 0.70
            if age_days < 730:
                return 0.40

        # Old CVE (>= 730 days) or fallback
        return 0.80 if has_kev else 0.15

    @staticmethod
    def _classify(score: float, path: AttackPath, metadata: dict) -> str:
        """Classify path risk with constraint 22 (unvalidated cap)."""
        validated_count = sum(1 for s in path.steps if s.validated)
        if validated_count == 0 and score < 0.40:
            return "speculative"

        # Constraint 22: unvalidated paths with no external signal
        # cannot reach high/critical — capped at medium
        if validated_count == 0 and score >= 0.70:
            has_signal = (
                metadata.get("has_cisa_kev", False)
                or metadata.get("has_poc", False)
                or metadata.get("has_exploit_url", False)
                or metadata.get("has_metasploit", False)
            )
            if not has_signal:
                return "medium"

        if score > 0.85:
            return "critical"
        if score > 0.70:
            return "high"
        if score > 0.50:
            return "medium"
        return "low"

    def sort_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """Sort descending by score; speculative paths always last."""
        def sort_key(p: AttackPath):
            return (1 if p.risk != "speculative" else 0, p.score)
        return sorted(paths, key=sort_key, reverse=True)

    def deduplicate(self, paths: List[AttackPath], overlap_threshold: float = 0.75) -> List[AttackPath]:
        """
        Remove paths sharing >overlap_threshold step-pairs with a higher-scored path.
        Also drops paths scoring below 0.05.
        Input must be sorted descending by score before calling.
        """
        kept = []
        for path in paths:
            if path.score < 0.05:
                continue
            step_pairs = {(s.from_id, s.to_id) for s in path.steps}
            dominated = False
            for kept_path in kept:
                kept_pairs = {(s.from_id, s.to_id) for s in kept_path.steps}
                if step_pairs and len(step_pairs & kept_pairs) / len(step_pairs) > overlap_threshold:
                    dominated = True
                    break
            if not dominated:
                kept.append(path)
        return kept
