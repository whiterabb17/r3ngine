"""
Plugin lifecycle and authentication-extraction activities: per-tier plugin
lookup, plugin start/end logging and login-form extraction for a URL.
"""

from temporalio import activity

from reNgine.utils.logger import get_module_logger
from reNgine.utils.task import activity_heartbeat_safe
# get_proxy_list and _extract_login_forms are also imported inside
# extract_auth_for_url_activity; they stay module-level as test patch targets.
from reNgine.tasks.auth_discovery import _extract_login_forms  # noqa: F401
from reNgine.common_func import get_proxy_list, get_random_proxy  # noqa: F401
from reNgine.temporal.activities.core import _run_task

logger = get_module_logger(__name__)


@activity.defn(name="GetEnabledPluginsForTierActivity")
def get_enabled_plugins_for_tier_activity(params: dict) -> list:
    """Return metadata for enabled plugins anchored to the given tier."""
    from plugins.models import Plugin

    tier = params.get("tier", "")
    selected_plugin_slugs = params.get("selected_plugin_slugs") or []

    logger.log_line("[TEMPORAL]", "START", "task=get_enabled_plugins tier=%s selected=%s" % (tier, selected_plugin_slugs))

    # No slugs selected for this scan — nothing to run.
    # The workflow helper already gates on this but we guard here too.
    if not selected_plugin_slugs:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_enabled_plugins tier=%s found=0 skipped=no_selection" % tier)
        return []

    results = []
    qs = Plugin.objects.filter(
        anchor_step=tier,
        runtime_position='AFTER',
        is_enabled=True,
        slug__in=selected_plugin_slugs,
    )
    plugins = qs.order_by('order_weight', 'id')

    for plugin in plugins:
        manifest = plugin.manifest or {}
        workflows = manifest.get('temporal', {}).get('workflows', [])
        if not workflows:
            continue
        workflow_path = workflows[0]
        if not isinstance(workflow_path, str) or not workflow_path.strip():
            logger.log_line("[TEMPORAL]", "WARN", "task=get_enabled_plugins invalid workflow path for plugin=%s" % plugin.slug)
            continue
        workflow_name = workflow_path.rsplit('.', 1)[-1]
        results.append({"slug": plugin.slug, "workflow_name": workflow_name})

    logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_enabled_plugins tier=%s found=%d" % (tier, len(results)))
    return results


@activity.defn(name="ExtractAuthForURLActivity")
def extract_auth_for_url_activity(ctx: dict) -> dict:
    from startScan.models import ScanHistory
    from urllib.parse import urlparse
    import time
    from reNgine.common_func import _failed_proxy_cache

    url = ctx.get('url')
    scan_id = ctx.get('scan_id')
    workflow_id = ctx.get('workflow_id')

    import json
    import redis
    from django.conf import settings
    from reNgine.tasks.auth_discovery import _extract_login_forms, _fetch_with_proxy_retry
    
    def push_auth_log(level, msg):
        logger.log_line("[AUTH_EXTRACT]", level, msg)
        if workflow_id:
            try:
                redis_url = getattr(settings, 'REDIS_URL', 'redis://redis:6379/0')
                client = redis.StrictRedis.from_url(redis_url)
                client.xadd(f"auth:logs:{workflow_id}", {"data": json.dumps({"line": f"[{level}] {msg}"})})
            except redis.RedisError:
                pass  # already logged above; only the live UI stream misses this line

    activity_heartbeat_safe("ExtractAuthForURLActivity starting for %s" % url)
    push_auth_log("START", "extracting auth from %s (scan %s)" % (url, scan_id))

    try:
        scan = ScanHistory.objects.filter(id=scan_id).first()
        if scan is None:
            push_auth_log("COMPLETE", "scan %s not found — skipping" % scan_id)
            return {'found': 0}

        current_proxy = get_random_proxy(http_only=True)
        if current_proxy:
            push_auth_log("INFO", "Retrieving proxy: %s" % current_proxy)

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            push_auth_log("COMPLETE", "skipped non-HTTP URL %s" % url)
            return {'found': 0}

        response = None
        try:
            push_auth_log("INFO", "Attempting extraction via %s" % (current_proxy if current_proxy else "direct fetch"))
            response, _ = _fetch_with_proxy_retry(url, [current_proxy] if current_proxy else [])
        except Exception as exc:
            if current_proxy:
                push_auth_log("WARNING", "Proxy %s failed. Cycling for a valid proxy..." % current_proxy)
                _failed_proxy_cache[current_proxy] = time.time()
                current_proxy = get_random_proxy(http_only=True)
                push_auth_log("INFO", "Getting new proxy: %s" % current_proxy)
                try:
                    push_auth_log("INFO", "Trying extraction again...")
                    response, _ = _fetch_with_proxy_retry(url, [current_proxy] if current_proxy else [])
                except Exception as retry_exc:
                    push_auth_log("ERROR", "Retry failed for %s: %s" % (url, str(retry_exc)))
                    push_auth_log("INFO", "Trying without proxy...")
                    try:
                        response, _ = _fetch_with_proxy_retry(url, [])
                    except Exception as final_exc:
                        push_auth_log("ERROR", "Direct fetch failed after proxy retry: %s" % str(final_exc))
                        raise final_exc
            else:
                push_auth_log("ERROR", "Direct fetch failed for %s: %s" % (url, str(exc)))
                raise exc

        if response is None:
            return {'found': 0}

        # Update http_status of the EndPoint if it is 0 or null
        from startScan.models import EndPoint
        endpoint_updated = False
        try:
            ep = EndPoint.objects.filter(scan_history=scan, http_url=url).first()
            if ep and (ep.http_status is None or ep.http_status == 0):
                ep.http_status = response.status_code
                ep.save()
                endpoint_updated = True
                push_auth_log("INFO", "Updated http_status to %d for auth endpoint %s" % (response.status_code, url))
        except Exception as e:
            push_auth_log("WARNING", "Could not update http_status for %s: %s" % (url, str(e)))

        push_auth_log("INFO", "Extracting forms....")
        forms = _extract_login_forms(response.text, url)

        if not forms:
            push_auth_log("COMPLETE", "no auth forms found at %s" % url)
            return {'found': 0}
        
        push_auth_log("COMPLETE", "Extraction complete.... Extracted inputs: %d forms found" % len(forms))

        raw_scheme = parsed_url.scheme.lower()
        protocol = raw_scheme
        port = parsed_url.port or (443 if raw_scheme == 'https' else 80)

        saved = 0
        for form in forms:
            from startScan.models import AuthCandidate, EndPoint
            ep = EndPoint.objects.filter(scan_history=scan, http_url=url).first()
            candidate, created = AuthCandidate.objects.get_or_create(
                scan_history=scan,
                target=form.get('action', url),
                protocol=protocol,
                port=port,
                defaults={
                    'source_tool': 'ExtractAuthForURLActivity',
                    'metadata': {
                        'type': 'form',
                        'method': form.get('method', 'POST'),
                        'user_field': form.get('user_field', ''),
                        'pass_field': form.get('pass_field', ''),
                        'hidden_fields': form.get('hidden_fields', {}),
                        'all_fields': form.get('all_fields', []),
                    },
                    'status': 'pending',
                    'endpoint': ep,
                    'subdomain': ep.subdomain if ep else None,
                },
            )
            if created:
                saved += 1
            else:
                if ep and not candidate.endpoint:
                    candidate.endpoint = ep
                    candidate.subdomain = ep.subdomain
                    candidate.save()

        # Trigger http_crawl again if it was status 0/None and forms were found
        if saved > 0 and endpoint_updated:
            from reNgine.tasks import http_crawl
            push_auth_log("INFO", "Running http_crawl for newly identified auth endpoint %s" % url)
            try:
                _run_task(
                    http_crawl,
                    ctx,
                    task_name='http_crawl_auth',
                    description='HTTP Crawl for Auth Endpoint',
                    urls=[url],
                    recrawl=True
                )
            except Exception as crawl_exc:
                push_auth_log("WARNING", "http_crawl submission failed for %s: %s" % (url, str(crawl_exc)))

        push_auth_log("COMPLETE", "saved %d candidate(s) for %s" % (saved, url))
        return {'found': saved}

    except Exception as exc:
        push_auth_log("ERROR", "Unhandled exception in extract_auth_for_url_activity: %s" % str(exc))
        raise


# ===========================================================================
# Plugin Lifecycle Logging
# ===========================================================================

@activity.defn(name="LogPluginStartActivity")
def log_plugin_start_activity(ctx: dict) -> dict:
    from startScan.models import ScanActivity
    from reNgine.definitions import RUNNING_TASK
    from django.utils import timezone
    scan_id = ctx.get("scan_id")
    name = ctx.get("name")
    title = ctx.get("title")
    tier_str = ctx.get("tier")
    tier_num = 7
    if tier_str and tier_str.startswith("tier_"):
        try:
            tier_num = int(tier_str.split("_")[1])
        except ValueError:
            pass
            
    now = timezone.now()
    execution_id = "temporal-" + activity.info().activity_id
    
    act = ScanActivity.objects.create(
        scan_of_id=scan_id,
        name=name,
        title=title,
        status=RUNNING_TASK,
        time=now,
        time_started=now,
        tier=tier_num,
        execution_id=execution_id,
    )
    return {"activity_id": act.id}


@activity.defn(name="LogPluginEndActivity")
def log_plugin_end_activity(ctx: dict) -> None:
    from startScan.models import ScanActivity
    from django.utils import timezone
    act_id = ctx.get("activity_id")
    status = ctx.get("status")
    error = ctx.get("error")
    try:
        act = ScanActivity.objects.get(id=act_id)
        act.status = status
        act.time_ended = timezone.now()
        act.error_message = error
        act.save(update_fields=['status', 'time_ended', 'error_message'])
    except Exception:
        logger.warning("Could not close plugin ScanActivity %s", act_id, exc_info=True)
