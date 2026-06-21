from neo4j import GraphDatabase
import logging
from django.conf import settings
from startScan.models import Subdomain, EndPoint
from targetApp.models import Domain

logger = logging.getLogger(__name__)

# Rows per Neo4j UNWIND transaction — keeps memory and txn duration bounded.
GRAPH_SYNC_BATCH_SIZE = 500
# ORM read chunk — separate from Neo4j batch size.
GRAPH_SYNC_ORM_CHUNK = 2000


def _chunk_list(items, size=GRAPH_SYNC_BATCH_SIZE):
    """Yield fixed-size slices from a list."""
    for offset in range(0, len(items), size):
        yield items[offset:offset + size]


def _graph_heartbeat(message, *details):
    """Send a Temporal heartbeat when running inside an activity context."""
    try:
        from temporalio import activity
        if details:
            activity.heartbeat(message, *details)
        else:
            activity.heartbeat(message)
    except Exception:
        pass


def _last_graph_sync_scan_id():
    """Return the last scan_id checkpoint from a prior activity heartbeat, if any."""
    try:
        from temporalio import activity
        details = activity.info().heartbeat_details
        if details:
            return int(details[0])
    except Exception:
        pass
    return 0


def _scan_severity_summary(scan_id: int) -> str:
    """Return a one-line severity/CVE breakdown for a scan, e.g.
    'Critical: 2 High: 5 Medium: 12 Low: 8 Unknown: 1 CVEs: 3'
    """
    from startScan.models import Vulnerability
    from django.db.models import Count

    qs = Vulnerability.objects.filter(scan_history_id=scan_id)
    counts = dict(
        qs.values_list('severity')
          .annotate(n=Count('id'))
          .values_list('severity', 'n')
    )
    cve_count = (
        qs.filter(cve_ids__isnull=False)
          .values('cve_ids')
          .distinct()
          .count()
    )
    return (
        f"Critical: {counts.get(4, 0)} "
        f"High: {counts.get(3, 0)} "
        f"Medium: {counts.get(2, 0)} "
        f"Low: {counts.get(1, 0)} "
        f"Unknown: {counts.get(-1, 0)} "
        f"CVEs: {cve_count}"
    )

# Suppress Neo4j notification logs (like CartesianProduct) unless DEBUG is enabled
import os
if os.environ.get("DEBUG", "0") != "1":
    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)


class Neo4jManager:
    def __init__(self):
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = settings.NEO4J_PASSWORD
        self.driver = None
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                connection_timeout=10,           # fail fast if Neo4j is unreachable
                max_transaction_retry_time=30,   # don't retry failed txns for >30s
            )
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def _ensure_graph_indexes(self, session):
        """Create lookup indexes once so large UNWIND MATCH steps do not table-scan."""
        index_statements = [
            "CREATE INDEX graph_subdomain_name IF NOT EXISTS FOR (n:Subdomain) ON (n.name)",
            "CREATE INDEX graph_endpoint_url IF NOT EXISTS FOR (n:Endpoint) ON (n.url)",
            "CREATE INDEX graph_scan_id IF NOT EXISTS FOR (n:Scan) ON (n.id)",
            "CREATE INDEX graph_vuln_id IF NOT EXISTS FOR (n:Vulnerability) ON (n.id)",
            "CREATE INDEX graph_exposure_id IF NOT EXISTS FOR (n:Exposure) ON (n.id)",
            "CREATE INDEX graph_domain_name IF NOT EXISTS FOR (n:Domain) ON (n.name)",
            "CREATE INDEX graph_ip_address IF NOT EXISTS FOR (n:IPAddress) ON (n.address)",
        ]
        for statement in index_statements:
            try:
                session.run(statement)
            except Exception as exc:
                logger.debug("Neo4j index statement skipped: %s (%s)", statement, exc)

    def _batch_execute(self, session, write_fn, rows, label="", heartbeat_callback=None):
        """Flush rows to Neo4j in bounded UNWIND batches."""
        if not rows:
            return
        total_batches = (len(rows) + GRAPH_SYNC_BATCH_SIZE - 1) // GRAPH_SYNC_BATCH_SIZE
        for batch_idx, chunk in enumerate(_chunk_list(rows, GRAPH_SYNC_BATCH_SIZE), start=1):
            session.execute_write(write_fn, chunk)
            logger.info(
                "[Neo4j] %s batch %d/%d (%d rows)",
                label, batch_idx, total_batches, len(chunk),
            )
            if heartbeat_callback:
                heartbeat_callback(
                    f"neo4j {label} batch {batch_idx}/{total_batches} ({len(chunk)} rows)"
                )

    def _flush_row_buffers(self, session, buffers, heartbeat_callback=None):
        """Write any pending row buffers to Neo4j."""
        for write_fn, rows, label in buffers:
            self._batch_execute(
                session, write_fn, rows, label=label, heartbeat_callback=heartbeat_callback,
            )

    def sync_scan_results(self, scan_history_id, heartbeat_callback=None):
        """Sync scan results from PostgreSQL to Neo4j.

        Streams ORM rows and writes Neo4j UNWIND batches so large scans do not
        load everything into memory or hold a single long-running transaction.
        """
        if not self.driver:
            return

        from startScan.models import ScanHistory, Vulnerability

        heartbeat = heartbeat_callback or _graph_heartbeat

        try:
            scan = ScanHistory.objects.select_related(
                'domain__project'
            ).get(id=scan_history_id)
            project_id = scan.domain.project.id if scan.domain and scan.domain.project else 0
            project_name = scan.domain.project.name if scan.domain and scan.domain.project else "Default Project"
            target_name = scan.domain.name if scan.domain else "Unknown Target"
            scan_date = (
                scan.start_scan_date.isoformat() if scan.start_scan_date else None
            )
        except Exception as e:
            logger.error(f"Failed to fetch scan details for sync: {e}")
            return

        subdomain_count = 0
        endpoint_count = 0
        param_count = 0
        tech_count = 0
        vuln_count = 0
        cve_count = 0

        with self.driver.session() as session:
            self._ensure_graph_indexes(session)
            session.execute_write(
                self._initialize_scan_context,
                project_id,
                project_name,
                scan_history_id,
                target_name,
                scan_date,
            )
            heartbeat(f"neo4j scan_id={scan_history_id} scaffold ready")

            subdomain_rows = []
            ip_rows = []
            tech_rows = []
            subdomain_base_qs = Subdomain.objects.filter(scan_history_id=scan_history_id)

            for row in subdomain_base_qs.values(
                'name', 'target_domain__name'
            ).iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                subdomain_name = row['name'] or "unknown"
                domain_name = row['target_domain__name'] or target_name
                subdomain_rows.append({
                    "domain_name": domain_name,
                    "subdomain_name": subdomain_name,
                    "scan_id": scan_history_id,
                })
                subdomain_count += 1
                if len(subdomain_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_subdomains, subdomain_rows,
                        label="subdomains", heartbeat_callback=heartbeat,
                    )
                    subdomain_rows = []

            for row in subdomain_base_qs.values(
                'name', 'ip_addresses__address'
            ).iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                ip = row.get('ip_addresses__address')
                if not ip:
                    continue
                ip_rows.append({
                    "ip": ip,
                    "subdomain_name": row['name'] or "unknown",
                    "scan_id": scan_history_id,
                })
                if len(ip_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_ips, ip_rows,
                        label="ips", heartbeat_callback=heartbeat,
                    )
                    ip_rows = []

            for row in subdomain_base_qs.values(
                'name', 'technologies__name'
            ).iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                tech_name = row.get('technologies__name')
                if not tech_name:
                    continue
                tech_rows.append({
                    "subdomain_name": row['name'] or "unknown",
                    "tech_name": tech_name,
                    "scan_id": scan_history_id,
                })
                tech_count += 1
                if len(tech_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_technologies, tech_rows,
                        label="technologies", heartbeat_callback=heartbeat,
                    )
                    tech_rows = []

            self._flush_row_buffers(session, [
                (self._batch_merge_subdomains, subdomain_rows, "subdomains"),
                (self._batch_merge_ips, ip_rows, "ips"),
                (self._batch_merge_technologies, tech_rows, "technologies"),
            ], heartbeat_callback=heartbeat)

            endpoint_rows = []
            param_rows = []
            endpoints_qs = EndPoint.objects.filter(scan_history_id=scan_history_id)
            endpoint_total = endpoints_qs.count()
            logger.info(
                "[Neo4j] scan_id=%s syncing %d endpoints",
                scan_history_id, endpoint_total,
            )

            for row in endpoints_qs.values(
                'http_url', 'subdomain__name'
            ).iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                endpoint_rows.append({
                    "subdomain_name": row['subdomain__name'] or target_name,
                    "url": row['http_url'] or "unknown",
                    "scan_id": scan_history_id,
                })
                endpoint_count += 1
                if endpoint_count % 10000 == 0:
                    logger.info(
                        "[Neo4j] scan_id=%s endpoints read %d/%d",
                        scan_history_id, endpoint_count, endpoint_total,
                    )
                    heartbeat(
                        f"neo4j scan_id={scan_history_id} endpoints {endpoint_count}/{endpoint_total}"
                    )
                if len(endpoint_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_endpoints, endpoint_rows,
                        label="endpoints", heartbeat_callback=heartbeat,
                    )
                    endpoint_rows = []

            exposure_rows = []
            from startScan.models import Exposure
            exposures_qs = Exposure.objects.filter(scan_history_id=scan_history_id)
            for row in exposures_qs.values('id', 'type', 'status', 'risk_score', 'subdomain__name').iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                exposure_rows.append({
                    "exposure_id": row['id'],
                    "type": row['type'],
                    "status": row['status'],
                    "risk_score": row['risk_score'],
                    "subdomain_name": row['subdomain__name'] or target_name,
                    "scan_id": scan_history_id
                })
                if len(exposure_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_exposures, exposure_rows,
                        label="exposures", heartbeat_callback=heartbeat,
                    )
                    exposure_rows = []

            from startScan.models import Parameter
            if Parameter.objects.filter(endpoint__scan_history_id=scan_history_id).exists():
                for row in Parameter.objects.filter(
                    endpoint__scan_history_id=scan_history_id
                ).values('name', 'type', 'endpoint__http_url').iterator(
                    chunk_size=GRAPH_SYNC_ORM_CHUNK
                ):
                    param_rows.append({
                        "url": row['endpoint__http_url'] or "unknown",
                        "param_name": row['name'] or "unknown",
                        "param_type": row['type'],
                        "scan_id": scan_history_id,
                    })
                    param_count += 1
                    if len(param_rows) >= GRAPH_SYNC_BATCH_SIZE:
                        self._batch_execute(
                            session, self._batch_merge_parameters, param_rows,
                            label="parameters", heartbeat_callback=heartbeat,
                        )
                        param_rows = []

            self._flush_row_buffers(session, [
                (self._batch_merge_endpoints, endpoint_rows, "endpoints"),
                (self._batch_merge_exposures, exposure_rows, "exposures"),
                (self._batch_merge_parameters, param_rows, "parameters"),
            ], heartbeat_callback=heartbeat)

            vuln_rows = []
            cve_rows = []
            vulns_qs = Vulnerability.objects.filter(scan_history_id=scan_history_id)

            for row in vulns_qs.values(
                'id', 'name', 'severity', 'correlation_score',
                'subdomain__name', 'endpoint__http_url', 'exposure_id'
            ).iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                if row['subdomain__name']:
                    asset_name = row['subdomain__name']
                    asset_type = "Subdomain"
                elif row['endpoint__http_url']:
                    asset_name = row['endpoint__http_url']
                    asset_type = "Endpoint"
                else:
                    continue

                vuln_rows.append({
                    "asset_name": asset_name,
                    "asset_type": asset_type,
                    "vuln_name": row['name'] or "Unknown Vulnerability",
                    "severity": row['severity'],
                    "score": row['correlation_score'],
                    "exposure_id": row.get('exposure_id'),
                    "scan_id": scan_history_id,
                    "vuln_id": row['id'],
                })
                vuln_count += 1
                if len(vuln_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_vulnerabilities, vuln_rows,
                        label="vulnerabilities", heartbeat_callback=heartbeat,
                    )
                    vuln_rows = []

            for row in vulns_qs.values(
                'id',
                'cve_ids__name',
                'cve_ids__cvss_v31_base_score',
                'cve_ids__epss_score',
                'cve_ids__is_cisa_kev',
                'cve_ids__published_date',
                'cve_ids__attack_vector',
            ).iterator(chunk_size=GRAPH_SYNC_ORM_CHUNK):
                cve_name = row.get('cve_ids__name')
                if not cve_name:
                    continue
                published = row.get('cve_ids__published_date')
                cve_rows.append({
                    "vuln_id": row['id'],
                    "cve_name": cve_name,
                    "cvss_score": row.get('cve_ids__cvss_v31_base_score'),
                    "epss_score": row.get('cve_ids__epss_score'),
                    "is_cisa_kev": row.get('cve_ids__is_cisa_kev'),
                    "published_date": published.isoformat() if published else None,
                    "attack_vector": row.get('cve_ids__attack_vector'),
                    "scan_id": scan_history_id,
                })
                cve_count += 1
                if len(cve_rows) >= GRAPH_SYNC_BATCH_SIZE:
                    self._batch_execute(
                        session, self._batch_merge_cves, cve_rows,
                        label="cves", heartbeat_callback=heartbeat,
                    )
                    cve_rows = []

            self._flush_row_buffers(session, [
                (self._batch_merge_vulnerabilities, vuln_rows, "vulnerabilities"),
                (self._batch_merge_cves, cve_rows, "cves"),
            ], heartbeat_callback=heartbeat)

        heartbeat(f"neo4j scan_id={scan_history_id} complete")
        logger.info(
            f"[Neo4j] sync_scan_results scan_id={scan_history_id}: "
            f"{subdomain_count} subdomains, {endpoint_count} endpoints, "
            f"{param_count} params, {tech_count} techs, "
            f"{vuln_count} vulns, {cve_count} CVEs synced."
        )

    @staticmethod
    def _initialize_scan_context(
        tx, project_id, project_name, scan_id, target_name, scan_date
    ):
        # Create Project
        tx.run(
            "MERGE (p:Project {id: $id}) SET p.name = $name",
            id=project_id,
            name=project_name,
        )
        # Create Target (Domain)
        tx.run("MERGE (d:Domain {name: $name})", name=target_name)
        # Create Scan
        tx.run(
            "MERGE (s:Scan {id: $id}) SET s.date = $date", id=scan_id, date=scan_date
        )
        # Link Scan to Project and Target
        tx.run(
            """
            MATCH (p:Project {id: $project_id}), (s:Scan {id: $scan_id}), (d:Domain {name: $target_name})
            MERGE (s)-[:BELONGS_TO]->(p)
            MERGE (s)-[:TARGETS]->(d)
        """,
            project_id=project_id,
            scan_id=scan_id,
            target_name=target_name,
        )

    @staticmethod
    def _merge_assets(tx, domain_name, subdomain_name, ip_address, scan_id):
        # Create Domain
        tx.run("MERGE (d:Domain {name: $name})", name=domain_name)

        # Create Subdomain and link to Domain
        tx.run(
            """
            MERGE (s:Subdomain {name: $sub_name})
            WITH s
            MATCH (d:Domain {name: $dom_name}), (sc:Scan {id: $scan_id})
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            MERGE (sc)-[:FOUND]->(s)
            MERGE (sc)-[:FOUND]->(d)
        """,
            sub_name=subdomain_name,
            dom_name=domain_name,
            scan_id=scan_id,
        )

        # If IP address exists, link it
        if ip_address:
            ips = [ip.strip() for ip in str(ip_address).split(",")]
            for ip in ips:
                tx.run(
                    """
                    MERGE (i:IPAddress {address: $ip})
                    WITH i
                    MATCH (s:Subdomain {name: $sub_name}), (sc:Scan {id: $scan_id})
                    MERGE (s)-[:RESOLVES_TO]->(i)
                    MERGE (sc)-[:FOUND]->(i)
                """,
                    ip=ip,
                    sub_name=subdomain_name,
                    scan_id=scan_id,
                )

    @staticmethod
    def _merge_endpoints(tx, subdomain_name, http_url, scan_id):
        tx.run(
            """
            MERGE (e:Endpoint {url: $url})
            WITH e
            MATCH (s:Subdomain {name: $sub_name}), (sc:Scan {id: $scan_id})
            MERGE (s)-[:HAS_ENDPOINT]->(e)
            MERGE (sc)-[:FOUND]->(e)
        """,
            url=http_url,
            sub_name=subdomain_name,
            scan_id=scan_id,
        )

    @staticmethod
    def _merge_parameters(tx, endpoint_url, param_name, param_type, scan_id):
        tx.run(
            """
            MERGE (p:Parameter {name: $name, type: $type})
            WITH p
            MATCH (e:Endpoint {url: $url}), (sc:Scan {id: $scan_id})
            MERGE (e)-[:HAS_PARAMETER]->(p)
            MERGE (sc)-[:FOUND]->(p)
        """,
            name=param_name,
            type=param_type,
            url=endpoint_url,
            scan_id=scan_id,
        )

    @staticmethod
    def _merge_technologies(tx, subdomain_name, tech_name, scan_id):
        tx.run(
            """
            MERGE (t:Technology {name: $tech_name})
            WITH t
            MATCH (s:Subdomain {name: $sub_name}), (sc:Scan {id: $scan_id})
            MERGE (s)-[:USES_TECH]->(t)
            MERGE (sc)-[:FOUND]->(t)
        """,
            tech_name=tech_name,
            sub_name=subdomain_name,
            scan_id=scan_id,
        )

    @staticmethod
    def _merge_vulnerabilities(
        tx,
        asset_name,
        asset_type,
        vuln_name,
        severity,
        correlation_score,
        scan_id,
        vuln_id,
    ):
        tx.run(
            f"""
            MERGE (v:Vulnerability {{id: $vuln_id}})
            SET v.name = $vuln_name, v.severity = $severity, v.correlation_score = $score
            WITH v
            MATCH (a:{asset_type} {{name: $asset_name}}), (sc:Scan {{id: $scan_id}})
            MERGE (a)-[:HAS_VULNERABILITY]->(v)
            MERGE (sc)-[:FOUND]->(v)
        """,
            vuln_id=vuln_id,
            vuln_name=vuln_name,
            severity=severity,
            score=correlation_score,
            asset_name=asset_name,
            scan_id=scan_id,
        )

    @staticmethod
    def _merge_cves(tx, vuln_id, cve_name, scan_id):
        tx.run(
            """
            MERGE (c:CVE {name: $cve_name})
            WITH c
            MATCH (v:Vulnerability {id: $vuln_id}), (sc:Scan {id: $scan_id})
            MERGE (v)-[:LINKED_TO_CVE]->(c)
            MERGE (sc)-[:FOUND]->(c)
        """,
            cve_name=cve_name,
            vuln_id=vuln_id,
            scan_id=scan_id,
        )

    # ------------------------------------------------------------------
    # Batched UNWIND write helpers — one transaction per entity type.
    # rows is a list of dicts; keys match the Cypher parameter names.
    # ------------------------------------------------------------------

    @staticmethod
    def _batch_merge_subdomains(tx, rows):
        """Merge all subdomains for a scan in a single UNWIND transaction."""
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (d:Domain {name: row.domain_name})
            MERGE (s:Subdomain {name: row.subdomain_name})
            WITH d, s, row
            MATCH (sc:Scan {id: row.scan_id})
            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            MERGE (sc)-[:FOUND]->(s)
            MERGE (sc)-[:FOUND]->(d)
            """,
            rows=rows,
        )

    @staticmethod
    def _batch_merge_ips(tx, rows):
        """Merge all IP-address nodes for a scan in a single UNWIND transaction."""
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (i:IPAddress {address: row.ip})
            WITH i, row
            MATCH (s:Subdomain {name: row.subdomain_name}), (sc:Scan {id: row.scan_id})
            MERGE (s)-[:RESOLVES_TO]->(i)
            MERGE (sc)-[:FOUND]->(i)
            """,
            rows=rows,
        )

    @staticmethod
    def _batch_merge_technologies(tx, rows):
        """Merge all technology nodes for a scan in a single UNWIND transaction."""
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (t:Technology {name: row.tech_name})
            WITH t, row
            MATCH (s:Subdomain {name: row.subdomain_name}), (sc:Scan {id: row.scan_id})
            MERGE (s)-[:USES_TECH]->(t)
            MERGE (sc)-[:FOUND]->(t)
            """,
            rows=rows,
        )

    @staticmethod
    def _batch_merge_endpoints(tx, rows):
        """Merge all endpoint nodes for a scan in a single UNWIND transaction."""
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (e:Endpoint {url: row.url})
            WITH e, row
            MATCH (s:Subdomain {name: row.subdomain_name}), (sc:Scan {id: row.scan_id})
            MERGE (s)-[:HAS_ENDPOINT]->(e)
            MERGE (sc)-[:FOUND]->(e)
            """,
            rows=rows,
        )

    @staticmethod
    def _batch_merge_parameters(tx, rows):
        """Merge all parameter nodes for a scan in a single UNWIND transaction."""
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (p:Parameter {name: row.param_name, type: row.param_type})
            WITH p, row
            MATCH (e:Endpoint {url: row.url}), (sc:Scan {id: row.scan_id})
            MERGE (e)-[:HAS_PARAMETER]->(p)
            MERGE (sc)-[:FOUND]->(p)
            """,
            rows=rows,
        )

    @staticmethod
    def _batch_merge_vulnerabilities(tx, rows):
        """Merge all vulnerability nodes for a scan in a single UNWIND transaction.

        Neo4j does not support dynamic node labels inside UNWIND, so we split
        subdomain-linked and endpoint-linked vulns into two separate runs.
        """
        subdomain_rows = [r for r in rows if r["asset_type"] == "Subdomain"]
        endpoint_rows = [r for r in rows if r["asset_type"] == "Endpoint"]

        if subdomain_rows:
            tx.run(
                """
                UNWIND $rows AS row
                MERGE (v:Vulnerability {id: row.vuln_id})
                SET v.name = row.vuln_name, v.severity = row.severity,
                    v.correlation_score = row.score
                WITH v, row
                MATCH (a:Subdomain {name: row.asset_name}), (sc:Scan {id: row.scan_id})
                MERGE (a)-[:HAS_VULNERABILITY]->(v)
                MERGE (sc)-[:FOUND]->(v)
                WITH v, row
                WHERE row.exposure_id IS NOT NULL
                MATCH (e:Exposure {id: row.exposure_id})
                MERGE (e)-[:HAS_VULNERABILITY]->(v)
                """,
                rows=subdomain_rows,
            )
        if endpoint_rows:
            tx.run(
                """
                UNWIND $rows AS row
                MERGE (v:Vulnerability {id: row.vuln_id})
                SET v.name = row.vuln_name, v.severity = row.severity,
                    v.correlation_score = row.score
                WITH v, row
                MATCH (a:Endpoint {url: row.asset_name}), (sc:Scan {id: row.scan_id})
                MERGE (a)-[:HAS_VULNERABILITY]->(v)
                MERGE (sc)-[:FOUND]->(v)
                WITH v, row
                WHERE row.exposure_id IS NOT NULL
                MATCH (e:Exposure {id: row.exposure_id})
                MERGE (e)-[:HAS_VULNERABILITY]->(v)
                """,
                rows=endpoint_rows,
            )

    @staticmethod
    def _batch_merge_exposures(tx, rows):
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (e:Exposure {id: row.exposure_id})
            SET e.type = row.type, e.status = row.status, e.risk_score = row.risk_score
            WITH e, row
            MATCH (s:Subdomain {name: row.subdomain_name}), (sc:Scan {id: row.scan_id})
            MERGE (s)-[:HAS_EXPOSURE]->(e)
            MERGE (sc)-[:FOUND]->(e)
            """,
            rows=rows,
        )

    @staticmethod
    def _batch_merge_cves(tx, rows):
        """Merge all CVE nodes for a scan in a single UNWIND transaction."""
        tx.run(
            """
            UNWIND $rows AS row
            MERGE (c:CVE {name: row.cve_name})
            SET c.cvss_score = row.cvss_score,
                c.epss_score = row.epss_score,
                c.is_cisa_kev = row.is_cisa_kev,
                c.published = row.published_date,
                c.attack_vector = row.attack_vector
            WITH c, row
            MATCH (v:Vulnerability {id: row.vuln_id}), (sc:Scan {id: row.scan_id})
            MERGE (v)-[:LINKED_TO_CVE]->(c)
            MERGE (sc)-[:FOUND]->(c)
            """,
            rows=rows,
        )

    def ingest_stress_telemetry(self, endpoint_url, scan_id, telemetry_data):
        """
        telemetry_data = {
            'tool': 'k6',
            'concurrent_users': 100,
            'avg_latency': 120.5,
            'p95_latency': 200.0,
            'error_rate': 0.05,
            'total_requests': 5000,
            'throughput_rps': 150.5
        }
        """
        if not self.driver:
            return

        with self.driver.session() as session:
            session.execute_write(
                self._merge_stress_telemetry, endpoint_url, scan_id, telemetry_data
            )

    @staticmethod
    def _merge_stress_telemetry(tx, endpoint_url, scan_id, data):
        tx.run(
            """
            MERGE (st:StressTest {scan_id: $scan_id, endpoint_url: $url, tool: $tool})
            SET st.concurrent_users = $concurrent_users,
                st.avg_latency = $avg_latency,
                st.p95_latency = $p95_latency,
                st.error_rate = $error_rate,
                st.total_requests = $total_requests,
                st.throughput_rps = $throughput_rps
            WITH st
            MATCH (e:Endpoint {url: $url}), (sc:Scan {id: $scan_id})
            MERGE (e)-[:STRESS_TESTED_BY]->(st)
            MERGE (sc)-[:FOUND]->(st)
        """,
            url=endpoint_url,
            scan_id=scan_id,
            tool=data.get("tool", "unknown"),
            concurrent_users=data.get("concurrent_users", 0),
            avg_latency=data.get("avg_latency", 0.0),
            p95_latency=data.get("p95_latency", 0.0),
            error_rate=data.get("error_rate", 0.0),
            total_requests=data.get("total_requests", 0),
            throughput_rps=data.get("throughput_rps", 0.0),
        )

    def get_stress_telemetry(self, scan_id):
        """Fetches stress test telemetry for a given scan."""
        if not self.driver:
            return []
        query = """
            MATCH (st:StressTest {scan_id: $scan_id})
            RETURN st
        """
        data = []
        try:
            with self.driver.session() as session:
                result = session.run(query, scan_id=scan_id)
                for record in result:
                    node = record["st"]
                    data.append(
                        {
                            "endpoint_url": node.get("endpoint_url"),
                            "tool": node.get("tool"),
                            "concurrent_users": node.get("concurrent_users"),
                            "avg_latency": node.get("avg_latency"),
                            "p95_latency": node.get("p95_latency"),
                            "error_rate": node.get("error_rate"),
                            "total_requests": node.get("total_requests"),
                            "throughput_rps": node.get("throughput_rps"),
                        }
                    )
        except Exception as e:
            logger.error(f"Failed to fetch stress telemetry: {e}")
        return data

    def sync_all_scans(self, heartbeat_callback=None, resume_from_scan_id=None):
        """Sync all scan results from PostgreSQL to Neo4j.

        Sends Temporal heartbeats per scan so large startup syncs stay alive.
        On activity retry, resumes after the last successfully synced scan_id.
        """
        from startScan.models import ScanHistory

        heartbeat = heartbeat_callback or _graph_heartbeat
        start_after_id = resume_from_scan_id
        if start_after_id is None:
            start_after_id = _last_graph_sync_scan_id()

        scans = (
            ScanHistory.objects
            .select_related('domain')
            .filter(id__gt=start_after_id)
            .order_by('id')
        )
        total_scans = scans.count()
        if start_after_id:
            logger.info(
                "Resuming global graph sync after scan_id=%s (%d scans remaining).",
                start_after_id, total_scans,
            )
        else:
            logger.info("Starting global graph synchronization for %d scans.", total_scans)

        for index, scan in enumerate(scans, 1):
            domain_name = scan.domain.name if scan.domain else "unknown"
            summary = _scan_severity_summary(scan.id)
            logger.info(
                "[%d/%d] Syncing scan #%d (%s) — %s",
                index, total_scans, scan.id, domain_name, summary,
            )
            heartbeat(f"graph sync starting scan {scan.id} ({index}/{total_scans})", scan.id)
            try:
                self.sync_scan_results(scan.id, heartbeat_callback=heartbeat)
            except Exception as e:
                logger.error("Failed to sync scan %d: %s", scan.id, e)
            heartbeat(f"graph sync completed scan {scan.id} ({index}/{total_scans})", scan.id)

        logger.info("Global graph synchronization completed successfully.")

    def get_cytoscape_json(self, scan_history_id):
        """Returns graph data in Cytoscape format for a specific scan."""
        query = """
            MATCH (sc:Scan {id: $scan_id})-[:FOUND]->(n)
            OPTIONAL MATCH (n)-[r]->(m)
            WHERE (sc)-[:FOUND]->(m)
            RETURN n, r, m
        """
        return self._fetch_graph_data(query, {"scan_id": int(scan_history_id)})

    def get_target_graph_data(self, target_name):
        """Returns graph data for all scans of a specific target (Domain)."""
        query = """
            MATCH (target:Domain {name: $target_name})<-[:TARGETS]-(sc:Scan)-[:FOUND]->(n)
            OPTIONAL MATCH (n)-[r]->(m)
            WHERE EXISTS {
               MATCH (sc2:Scan)-[:TARGETS]->(target)
               WHERE (sc2)-[:FOUND]->(m)
            }
            RETURN n, r, m, sc.id as scan_id
        """
        return self._fetch_graph_data(query, {"target_name": target_name})

    def get_impact_path(self, vuln_id):
        """Returns a subgraph showing the attack path from the domain to a specific vulnerability."""
        query = """
            MATCH (v:Vulnerability {id: $vuln_id})
            MATCH p = (d:Domain)-[*..4]->(v)
            WITH p, v
            UNWIND nodes(p) as n
            UNWIND relationships(p) as r
            RETURN DISTINCT n, r, endNode(r) as m
        """
        return self._fetch_graph_data(query, {"vuln_id": int(vuln_id)})

    def _fetch_graph_data(self, query, params):
        if not self.driver:
            return {"nodes": [], "edges": []}

        nodes_dict = {}
        edges = []
        color_map = {
            "Domain": "#3b82f6",
            "Subdomain": "#10b981",
            "IPAddress": "#f59e0b",
            "Vulnerability": "#ef4444",
            "Endpoint": "#8b5cf6",
            "Parameter": "#ec4899",
            "Technology": "#facc15",
            "CVE": "#7c3aed",
            "StressTest": "#14b8a6",
        }

        with self.driver.session() as session:
            result = session.run(query, **params)

            for record in result:
                scan_ids = record.get("scan_ids") or []
                if record.get("scan_id"):
                    scan_ids.append(record.get("scan_id"))

                for node_key in ["n", "m"]:
                    node = record[node_key]
                    if not node:
                        continue
                    node_id = str(node.id)
                    if node_id not in nodes_dict:
                        label = node.get("name") or node.get("address") or node.get("url") or node_id
                        node_type = list(node.labels)[0] if node.labels else "Unknown"
                        nodes_dict[node_id] = {
                            "data": {
                                "id": node_id,
                                "label": label,
                                "type": node_type,
                                "color": color_map.get(node_type, "#94a3b8"),
                                "scan_ids": scan_ids,
                                "degree_centrality": 0,
                                "criticalVulnCount": 0,
                                "highVulnCount": 0,
                                "severity": node.get("severity", -1),
                            }
                        }

                if record["r"]:
                    src = str(record["n"].id)
                    tgt = str(record["m"].id)
                    r_type = record["r"].type
                    edges.append(
                        {
                            "data": {
                                "source": src,
                                "target": tgt,
                                "label": r_type,
                                "scan_ids": scan_ids,
                            }
                        }
                    )
                    
                    # Compute degree centrality
                    if src in nodes_dict:
                        nodes_dict[src]["data"]["degree_centrality"] += 1
                    if tgt in nodes_dict:
                        nodes_dict[tgt]["data"]["degree_centrality"] += 1
                        
                    # Compute vulnerability counts
                    if r_type == "HAS_VULNERABILITY":
                        vuln_node = nodes_dict.get(tgt)
                        if vuln_node and vuln_node["data"]["type"] == "Vulnerability":
                            severity = vuln_node["data"].get("severity", -1)
                            if severity == 4:
                                nodes_dict[src]["data"]["criticalVulnCount"] += 1
                            elif severity == 3:
                                nodes_dict[src]["data"]["highVulnCount"] += 1

        return {"nodes": list(nodes_dict.values()), "edges": edges}

    def get_blast_radius(self, node_id):
        """Calculates the blast radius of a compromised node using APOC."""
        query = """
            MATCH (startNode) WHERE startNode.id = $node_id OR toString(id(startNode)) = $node_id
            CALL apoc.path.subgraphAll(startNode, {maxLevel: 3}) YIELD relationships
            UNWIND relationships as r
            RETURN startNode(r) as n, r, endNode(r) as m
        """
        return self._fetch_graph_data(query, {"node_id": str(node_id)})

    def get_node_details(self, node_id):
        """Fetches detailed properties for a single node."""
        if not self.driver:
            return {}

        query = """
            MATCH (n) WHERE toString(id(n)) = $node_id OR n.id = $node_id
            RETURN n, labels(n) as labels
        """
        with self.driver.session() as session:
            result = session.run(query, node_id=str(node_id))
            record = result.single()
            if record:
                node = record["n"]
                labels = record["labels"]
                return {
                    "id": str(node.id),
                    "labels": labels,
                    "properties": dict(node)
                }
        return {}

    def reset_database(self):
        """Deletes all nodes and relationships from the Neo4j database."""
        if not self.driver:
            return
        query = "MATCH (n) DETACH DELETE n"
        with self.driver.session() as session:
            session.run(query)
        logger.info("Neo4j database has been reset (all nodes deleted).")


def get_neo4j_driver():
    """Return a live Neo4j driver instance, or None if Neo4j is unreachable."""
    mgr = Neo4jManager()
    return mgr.driver
