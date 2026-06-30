import markdown
import requests
import logging
from reNgine.validators import validate_external_url
import os
import threading
from django.conf import settings

from weasyprint import HTML, CSS
from datetime import datetime
from django.contrib import messages
from django.db.models import Count, Case, When, IntegerField
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import get_template
from django.urls import reverse
from django.utils import timezone
from startScan.models import TemporalSchedule
from rolepermissions.decorators import has_permission_decorator


from reNgine.charts import *
from reNgine.common_func import *
from reNgine.definitions import ABORTED_TASK, SUCCESS_TASK, PERM_MODIFY_SCAN_REPORT, FOUR_OH_FOUR_URL
from reNgine.tasks import create_scan_activity, initiate_scan_temporal, run_command
from scanEngine.models import EngineType
from startScan.models import *
from targetApp.models import *
from reNgine.utils.graph import Neo4jManager

logger = logging.getLogger(__name__)


def scan_history(request, slug):
    host = ScanHistory.objects.filter(domain__project__slug=slug).order_by('-start_scan_date')
    context = {'scan_history_active': 'active', "scan_history": host}
    return render(request, 'dashboard/v3_index.html', context)


def subscan_history(request, slug):
    subscans = SubScan.objects.filter(scan_history__domain__project__slug=slug).order_by('-start_scan_date')
    context = {'scan_history_active': 'active', "subscans": subscans}
    return render(request, 'dashboard/v3_index.html', context)


def detail_scan(request, id, slug):
    ctx = {}

    # Get scan objects
    scan = get_object_or_404(ScanHistory, id=id)
    domain_id = scan.domain.id
    scan_engines = EngineType.objects.order_by('engine_name').all()
    recent_scans = ScanHistory.objects.filter(domain__id=domain_id)
    last_scans = (
        ScanHistory.objects
        .filter(domain__id=domain_id)
        .filter(tasks__overlap=['subdomain_discovery'])
        .filter(id__lte=id)
        .filter(scan_status=2)
    )

    # Get all kind of objects associated with our ScanHistory object
    emails = Email.objects.filter(emails__in=[scan])
    employees = Employee.objects.filter(employees__in=[scan])
    subdomains = Subdomain.objects.filter(scan_history=scan)
    endpoints = EndPoint.objects.filter(scan_history=scan)
    vulns = Vulnerability.objects.filter(scan_history=scan)
    vulns_tags = VulnerabilityTags.objects.filter(vuln_tags__in=vulns)
    ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains)
    geo_isos = CountryISO.objects.filter(ipaddress__in=ip_addresses)
    scan_activity = ScanActivity.objects.filter(scan_of__id=id).order_by('time')
    cves = CveId.objects.filter(cve_ids__in=vulns)
    cwes = CweId.objects.filter(cwe_ids__in=vulns)
    secret_leaks = SecretLeak.objects.filter(scan_history=scan)

    # HTTP statuses
    http_statuses = (
        subdomains
        .exclude(http_status=0)
        .values('http_status')
        .annotate(Count('http_status'))
    )

    # CVEs / CWes - Exclude empty or null entries to prevent displaying blanks in charts
    common_cves = (
        cves
        .exclude(name='')
        .exclude(name__isnull=True)
        .annotate(nused=Count('cve_ids'))
        .order_by('-nused')
        .values('name', 'nused')
        [:10]
    )
    common_cwes = (
        cwes
        .exclude(name='')
        .exclude(name__isnull=True)
        .annotate(nused=Count('cwe_ids'))
        .order_by('-nused')
        .values('name', 'nused')
        [:10]
    )

    # Tags
    common_tags = (
        vulns_tags
        .annotate(nused=Count('vuln_tags'))
        .order_by('-nused')
        .values('name', 'nused')
        [:7]
    )

    # Countries
    asset_countries = (
        geo_isos
        .annotate(count=Count('iso'))
        .order_by('-count')
    )

    # Subdomains
    subdomain_count = (
        subdomains
        .values('name')
        .distinct()
        .count()
    )
    alive_count = (
        subdomains
        .values('name')
        .distinct()
        .filter(http_status__exact=200)
        .count()
    )
    important_count = (
        subdomains
        .values('name')
        .distinct()
        .filter(is_important=True)
        .count()
    )

    # Endpoints
    endpoint_count = (
        endpoints
        .values('http_url')
        .distinct()
        .count()
    )
    endpoint_alive_count = (
        endpoints
        .filter(http_status__exact=200) # TODO: use is_alive() func as it's more precise
        .values('http_url')
        .distinct()
        .count()
    )

    # Vulnerabilities
    common_vulns = (
        vulns
        .exclude(severity=0)
        .values('name', 'severity')
        .annotate(count=Count('name'))
        .order_by('-count')
        [:10]
    )
    info_count = vulns.filter(severity=0).count()
    low_count = vulns.filter(severity=1).count()
    medium_count = vulns.filter(severity=2).count()
    high_count = vulns.filter(severity=3).count()
    critical_count = vulns.filter(severity=4).count()
    unknown_count = vulns.filter(severity=-1).count()
    total_count = vulns.count()
    total_count_ignore_info = vulns.exclude(severity=0).count()

    # Exploitable vulnerabilities
    exploitable_vulns = vulns.exclude(exploit_url__isnull=True).exclude(exploit_url__exact='')
    exploitable_count = exploitable_vulns.count()

    # Emails
    exposed_count = emails.exclude(password__isnull=True).count()

    # Build render context
    ctx = {
        'scan_history_id': id,
        'history': scan,
        'scan_activity': scan_activity,
        'subdomain_count': subdomain_count,
        'alive_count': alive_count,
        'important_count': important_count,
        'endpoint_count': endpoint_count,
        'endpoint_alive_count': endpoint_alive_count,
        'info_count': info_count,
        'low_count': low_count,
        'medium_count': medium_count,
        'high_count': high_count,
        'critical_count': critical_count,
        'unknown_count': unknown_count,
        'total_vulnerability_count': total_count,
        'total_vul_ignore_info_count': total_count_ignore_info,
        'exploitable_count': exploitable_count,
        'non_exploitable_count': total_count - exploitable_count,
        'vulnerability_list': vulns.order_by('-severity').all(),
        'scan_history_active': 'active',
        'scan_engines': scan_engines,
        'exposed_count': exposed_count,
        'email_count': emails.count(),
        'employees_count': employees.count(),
        'most_recent_scans': recent_scans.order_by('-start_scan_date')[:1],
        'http_status_breakdown': http_statuses,
        'most_common_cve': common_cves,
        'most_common_cwe': common_cwes,
        'most_common_tags': common_tags,
        'most_common_vulnerability': common_vulns,
        'asset_countries': asset_countries,
        'secret_leaks': secret_leaks.order_by('-discovered_date'),
        'secret_leaks_count': secret_leaks.count(),
    }

    # Find number of matched GF patterns
    if scan.used_gf_patterns:
        count_gf = {}
        for gf in scan.used_gf_patterns.split(','):
            count_gf[gf] = (
                endpoints
                .filter(matched_gf_patterns__icontains=gf)
                .count()
            )
            ctx['matched_gf_count'] = count_gf

    # Find last scan for this domain
    if last_scans.count() > 1:
        last_scan = last_scans.order_by('-start_scan_date')[1]
        ctx['last_scan'] = last_scan

    return render(request, 'dashboard/v3_index.html', ctx)


def all_subdomains(request, slug):
    subdomains = Subdomain.objects.filter(target_domain__project__slug=slug)
    scan_engines = EngineType.objects.order_by('engine_name').all()
    alive_subdomains = subdomains.filter(http_status__exact=200) # TODO: replace this with is_alive() function
    important_subdomains = (
        subdomains
        .filter(is_important=True)
        .values('name')
        .distinct()
        .count()
    )
    context = {
        'current_project': get_object_or_404(Project, slug=slug),
        'scan_history_id': '',
        'scan_history_active': 'active',
        'scan_engines': scan_engines,
        'subdomain_count': subdomains.values('name').distinct().count(),
        'alive_count': alive_subdomains.values('name').distinct().count(),
        'important_count': important_subdomains
    }
    return render(request, 'dashboard/v3_index.html', context)

def detail_vuln_scan(request, slug, id=None):
    if id:
        history = get_object_or_404(ScanHistory, id=id)
        history.filter(domain__project__slug=slug)
        context = {'scan_history_id': id, 'history': history}
    else:
        context = {'vuln_scan_active': 'true'}
    return render(request, 'dashboard/v3_index.html', context)


def all_endpoints(request, slug):
    context = {
        'scan_history_active': 'active'
    }
    return render(request, 'dashboard/v3_index.html', context)

@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_scan_ui(request, slug, domain_id):
    domain = get_object_or_404(Domain, id=domain_id)
    if request.method == "POST":
        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        custom_dorks = None
        if 'customDorkSwitch' in request.POST:
            custom_dorks = request.POST.get('customDorkTextarea', '').strip()

        spiderfoot_scan = 'spiderfoot_scan' in request.POST

        # Get engine type
        engine_id = request.POST['scan_mode']

        # Create ScanHistory object
        scan_history_id = create_scan_object(
            host_id=domain_id,
            engine_id=engine_id,
            initiated_by_id=request.user.id
        )
        scan = ScanHistory.objects.get(pk=scan_history_id)
        if custom_dorks:
            scan.cfg_custom_dorks = custom_dorks
            scan.save()

        # Start the scan via Temporal durable workflow orchestration.
        # initiate_scan_temporal performs the same scan bootstrap as the
        # legacy Celery initiate_scan, then starts a MasterScanWorkflow on
        # the Temporal cluster.
        kwargs = {
            'scan_history_id': scan.id,
            'domain_id': domain.id,
            'engine_id': engine_id,
            'scan_type': LIVE_SCAN,
            'results_dir': settings.RENGINE_RESULTS,
            'imported_subdomains': subdomains_in,
            'out_of_scope_subdomains': subdomains_out,
            'starting_point_path': starting_point_path,
            'excluded_paths': excluded_paths,
            'custom_dorks': custom_dorks,
            'enable_spiderfoot_scan': spiderfoot_scan,
            'initiated_by_id': request.user.id
        }
        initiate_scan_temporal(**kwargs)
        scan.save()

        # Send start notif
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Started for {domain.name}')
        return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

    # GET request

    is_rescan = request.GET.get('rescan', 'false').lower() == 'true'
    history_id = request.GET.get('history_id', None)

    # default values
    subdomains_in = []
    subdomains_out = []
    starting_point_path = None
    excluded_paths = []
    selected_engine_id = None

    if is_rescan and history_id:
        previous_scan = get_object_or_404(ScanHistory, id=history_id)
        selected_engine_id = getattr(previous_scan.scan_type, 'id', None)
        subdomains_in = getattr(previous_scan, 'cfg_imported_subdomains', None)
        subdomains_out = getattr(previous_scan, 'cfg_out_of_scope_subdomains', None)
        starting_point_path = getattr(previous_scan, 'cfg_starting_point_path', None)
        excluded_paths = getattr(previous_scan, 'cfg_excluded_paths', None)

    engines = EngineType.objects.order_by('engine_name')
    custom_engines_count = (
        EngineType.objects
        .filter(default_engine=False)
        .count()
    )
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS) if not excluded_paths else ','.join(excluded_paths)

    # context values
    context = {
        'scan_history_active': 'active',
        'domain': domain,
        'engines': engines,
        'custom_engines_count': custom_engines_count,
        'excluded_paths': excluded_paths,
        'subdomains_in': subdomains_in,
        'subdomains_out': subdomains_out,
        'starting_point_path': starting_point_path,
        'selected_engine_id': selected_engine_id,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_multiple_scan(request, slug):
    # domain = get_object_or_404(Domain, id=host_id)
    if request.method == "POST":
        if request.POST.get('scan_mode', 0):
            # if scan mode is available, then start the scan
            # get engine type
            engine_id = request.POST['scan_mode']
            list_of_domain_ids = request.POST['domain_ids']
            subdomains_in = request.POST['importSubdomainTextArea'].split()
            subdomains_in = [s.rstrip() for s in subdomains_in if s]
            subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
            subdomains_out = [s.rstrip() for s in subdomains_out if s]
            starting_point_path = request.POST['startingPointPath'].strip()
            excluded_paths = request.POST['excludedPaths'] # string separated by ,
            # split excluded paths by ,
            excluded_paths = [path.strip() for path in excluded_paths.split(',')]
            spiderfoot_scan = 'spiderfoot_scan' in request.POST

            grouped_scans = []

            for domain_id in list_of_domain_ids.split(","):
                # Start the celery task
                scan_history_id = create_scan_object(
                    host_id=domain_id,
                    engine_id=engine_id,
                    initiated_by_id=request.user.id
                )
                # domain = get_object_or_404(Domain, id=domain_id)

                kwargs = {
                    'scan_history_id': scan_history_id,
                    'domain_id': domain_id,
                    'engine_id': engine_id,
                    'scan_type': LIVE_SCAN,
                    'results_dir': settings.RENGINE_RESULTS,
                    'initiated_by_id': request.user.id,
                    'imported_subdomains': subdomains_in,
                    'out_of_scope_subdomains': subdomains_out,
                    'starting_point_path': starting_point_path,
                    'excluded_paths': excluded_paths,
                    'enable_spiderfoot_scan': spiderfoot_scan,
                }
                # Start each scan as an independent Temporal workflow
                initiate_scan_temporal(**kwargs)

            # Send start notif
            messages.add_message(
                request,
                messages.INFO,
                'Scan Started for multiple targets')

            return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

        else:
            # this else condition will have post request from the scan page
            # containing all the targets id
            list_of_domain_name = []
            list_of_domain_id = []
            for key, value in request.POST.items():
                if key != "list_target_table_length" and key != "csrfmiddlewaretoken":
                    domain = get_object_or_404(Domain, id=value)
                    list_of_domain_name.append(domain.name)
                    list_of_domain_id.append(value)
            domain_ids = ",".join(list_of_domain_id)

    # GET request
    engines = EngineType.objects
    custom_engine_count = (
        engines
        .filter(default_engine=False)
        .count()
    )
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    context = {
        'scan_history_active': 'active',
        'engines': engines,
        'domain_list': list_of_domain_name,
        'domain_ids': domain_ids,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'dashboard/v3_index.html', context)

@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def export_subdomains(request, scan_id):
    subdomain_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for domain in subdomain_list:
        response_body += response_body + domain.name + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="subdomains_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def export_endpoints(request, scan_id):
    endpoint_list = EndPoint.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for endpoint in endpoint_list:
        response_body += endpoint.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="endpoints_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def export_urls(request, scan_id):
    urls_list = Subdomain.objects.filter(scan_history__id=scan_id)
    scan = ScanHistory.objects.get(id=scan_id)
    response_body = ""
    for url in urls_list:
        if url.http_url:
            response_body += response_body + url.http_url + "\n"
    scan_start_date_str = str(scan.start_scan_date.date())
    domain_name = scan.domain.name
    response = HttpResponse(response_body, content_type='text/plain')
    response['Content-Disposition'] = (
        f'attachment; filename="urls_{domain_name}_{scan_start_date_str}.txt"'
    )
    return response


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scan(request, id):
    obj = get_object_or_404(ScanHistory, id=id)
    if request.method == "POST":
        delete_dir = obj.results_dir
        run_command('rm -rf ' + delete_dir, shell=True)
        obj.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Scan history successfully deleted!'
        )
    else:
        messageData = {'status': 'false'}
        messages.add_message(
            request,
            messages.INFO,
            'Oops! something went wrong!'
        )
    return JsonResponse(messageData)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def stop_scan(request, id):
    if request.method == "POST":
        scan = get_object_or_404(ScanHistory, id=id)
        try:
            from reNgine.temporal_client import TemporalClientProvider
            for te in scan.temporal_executions.filter(status="RUNNING"):
                try:
                    TemporalClientProvider.cancel_workflow(te.workflow_id)
                    te.status = "CANCELLED"
                    te.ended_at = timezone.now()
                    te.save()
                except Exception as cancel_err:
                    logger.warning(f"Temporal cancel failed for workflow {te.workflow_id}: {cancel_err}")
            scan.scan_status = ABORTED_TASK
            scan.save()
            tasks = (
                ScanActivity.objects
                .filter(scan_of=scan)
                .filter(status=RUNNING_TASK)
                .order_by('-pk')
            )
            for task in tasks:
                task.status = ABORTED_TASK
                task.time = timezone.now()
                task.save()
            create_scan_activity(scan.id, "Scan aborted", ABORTED_TASK)
            response = {'status': True}
            messages.add_message(
                request,
                messages.INFO,
                'Scan successfully stopped!'
            )
        except Exception as e:
            logger.error(e)
            response = {'status': False}
            messages.add_message(
                request,
                messages.ERROR,
                f'Scan failed to stop ! Error: {str(e)}'
            )
        return JsonResponse(response)
    return scan_history(request)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def resume_scan(request, id):
    if request.method == "POST":
        try:
            from reNgine.tasks import resume_scan_temporal
            scan = get_object_or_404(ScanHistory, id=id)
            resume_scan_temporal(scan.id)
            response = {'status': True}
            messages.add_message(
                request,
                messages.INFO,
                'Scan successfully resumed!'
            )
        except Exception as e:
            logger.error(e)
            response = {'status': False}
            messages.add_message(
                request,
                messages.ERROR,
                f'Scan failed to resume ! Error: {str(e)}'
            )
        return JsonResponse(response)
    return scan_history(request)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def stop_scans(request, slug):
    if request.method == "POST":
        from reNgine.utils.scan_cancellation import abort_scan_history
        for key, value in request.POST.items():
            if key == 'scan_history_table_length' or key == 'csrfmiddlewaretoken':
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            try:
                abort_scan_history(scan, aborted_by=request.user)
                messages.add_message(
                    request,
                    messages.INFO,
                    'Multiple scans successfully stopped!'
                )
            except Exception as e:
                logger.error(e)
                messages.add_message(
                    request,
                    messages.ERROR,
                    f'Scans failed to stop ! Error: {str(e)}'
                )
    return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))



@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_scan(request, host_id, slug):
    domain = Domain.objects.get(id=host_id)
    if request.method == "POST":
        scheduled_mode = request.POST['scheduled_mode']
        engine_type = int(request.POST['scan_mode'])

        # Get imported and out-of-scope subdomains
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        # Get engine type
        engine = get_object_or_404(EngineType, id=engine_type)
        timestr = str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
        task_name = f'{engine.engine_name} for {domain.name}: {timestr}'
        from reNgine.definitions import SCHEDULED_SCAN
        from reNgine.temporal_schedule_utils import (
            _create_periodic_temporal_schedule,
            _create_clocked_temporal_schedule,
            interval_to_seconds,
        )
        workflow_args = {
            'domain_id': host_id,
            'engine_id': engine.id,
            'scan_type': SCHEDULED_SCAN,
            'imported_subdomains': subdomains_in,
            'out_of_scope_subdomains': subdomains_out,
            'starting_point_path': starting_point_path,
            'excluded_paths': excluded_paths,
            'enable_spiderfoot_scan': 'spiderfoot_scan' in request.POST,
            'initiated_by_id': request.user.id,
        }
        if scheduled_mode == 'periodic':
            frequency_value = int(request.POST['frequency'])
            frequency_type = request.POST['frequency_type']
            _create_periodic_temporal_schedule(
                name=task_name,
                interval_seconds=interval_to_seconds(frequency_value, frequency_type),
                workflow_args=workflow_args,
                domain_id=host_id,
            )
        elif scheduled_mode == 'clocked':
            schedule_time = request.POST['scheduled_time']
            _create_clocked_temporal_schedule(
                name=task_name,
                clocked_time=schedule_time,
                workflow_args=workflow_args,
                domain_id=host_id,
            )
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Scheduled for {domain.name}'
        )
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))

    # GET request
    engines = EngineType.objects
    custom_engine_count = (
        engines
        .filter(default_engine=False)
        .count()
    )
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    context = {
        'scan_history_active': 'active',
        'domain': domain,
        'engines': engines,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'dashboard/v3_index.html', context)


def scheduled_scan_view(request, slug):
    scheduled_tasks = TemporalSchedule.objects.all()
    context = {
        'scheduled_scan_active': 'active',
        'scheduled_tasks': scheduled_tasks,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_task(request, id):
    task_object = get_object_or_404(TemporalSchedule, id=id)
    if request.method == "POST":
        from reNgine.temporal_schedule_utils import _delete_temporal_schedule_by_id
        try:
            _delete_temporal_schedule_by_id(task_object.schedule_id)
        except Exception as e:
            logger.error(f"[delete_scheduled_task] Temporal delete failed for '{task_object.schedule_id}': {e}")
        task_object.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Scheduled Scan successfully deleted!')
    else:
        messageData = {'status': 'false'}
        messages.add_message(
            request,
            messages.INFO,
            'Oops! something went wrong!')
    return JsonResponse(messageData)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scheduled_scans(request, slug):
    if request.method == "POST":
        from reNgine.temporal_schedule_utils import _delete_temporal_schedule_by_id
        for key, value in request.POST.items():
            if 'task' in key or key == 'csrfmiddlewaretoken':
                continue
            try:
                ts = TemporalSchedule.objects.get(id=value)
                try:
                    _delete_temporal_schedule_by_id(ts.schedule_id)
                except Exception as e:
                    logger.error(f"[delete_scheduled_scans] Temporal delete failed for '{ts.schedule_id}': {e}")
                ts.delete()
            except TemporalSchedule.DoesNotExist:
                logger.error(f"[delete_scheduled_scans] TemporalSchedule id={value} not found")
            except Exception as e:
                logger.error(e)
        messages.add_message(
            request,
            messages.INFO,
            'Multiple scheduled scans successfully deleted!')
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def change_scheduled_task_status(request, id):
    if request.method == 'POST':
        from reNgine.temporal_schedule_utils import _pause_temporal_schedule, _unpause_temporal_schedule
        try:
            ts = TemporalSchedule.objects.get(id=id)
            ts.is_active = not ts.is_active
            ts.save(update_fields=['is_active', 'updated_at'])
            try:
                if ts.is_active:
                    _unpause_temporal_schedule(ts.schedule_id)
                else:
                    _pause_temporal_schedule(ts.schedule_id)
            except Exception as e:
                logger.error(f"[change_scheduled_task_status] Temporal pause/unpause failed for '{ts.schedule_id}': {e}")
        except TemporalSchedule.DoesNotExist:
            pass
    return HttpResponse('')


def change_vuln_status(request, id):
    if request.method == 'POST':
        vuln = Vulnerability.objects.get(id=id)
        vuln.open_status = not vuln.open_status
        vuln.save()
    return HttpResponse('')


def update_vuln_validation_status(request, id):
    if request.method == 'POST':
        vuln = get_object_or_404(Vulnerability, id=id)
        status = request.POST.get('status')
        if status in ['unverified', 'verified', 'not_working', 'patched', 'closed']:
            vuln.validation_status = status
            vuln.save()
            return JsonResponse({'status': True})
    return JsonResponse({'status': False})


def fetch_exploit_source(request, id):
    vuln = get_object_or_404(Vulnerability, id=id)
    if vuln.exploit_url:
        try:
            validate_external_url(vuln.exploit_url)
            response = requests.get(vuln.exploit_url, timeout=10, verify=True)
            if response.status_code == 200:
                # If it's HTML, we might want to extract just the code if possible
                # But for now let's just return the text
                return JsonResponse({
                    'status': True,
                    'content': response.text
                })
            else:
                return JsonResponse({
                    'status': False,
                    'error': f'Failed to fetch exploit source. Status code: {response.status_code}'
                })
        except Exception as e:
            return JsonResponse({
                'status': False,
                'error': str(e)
            })
    return JsonResponse({
        'status': False,
        'error': 'No exploit URL found for this vulnerability.'
    })


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_scan_results(request):
    if request.method == 'POST':
        from reNgine.utils.scan_cancellation import abort_scan_history
        scans = list(ScanHistory.objects.all())
        for scan in scans:
            try:
                abort_scan_history(scan)
            except Exception:
                pass
            try:
                if scan.results_dir and os.path.exists(scan.results_dir):
                    import shutil
                    shutil.rmtree(scan.results_dir)
            except Exception:
                pass
            scan.delete()
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'All Scan History successfully deleted!')
    return JsonResponse(messageData)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_all_screenshots(request):
    if request.method == 'POST':
        run_command(f'rm -rf {settings.RENGINE_RESULTS}/*', shell=True)
        messageData = {'status': 'true'}
        messages.add_message(
            request,
            messages.INFO,
            'Screenshots successfully deleted!')
    return JsonResponse(messageData)


def visualise(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        'scan_id': id,
        'scan_history': scan,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def start_organization_scan(request, id, slug):
    organization = get_object_or_404(Organization, id=id)
    if request.method == "POST":
        engine_id = request.POST['scan_mode']

        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        # Start Temporal workflow for each organization's domains
        for domain in organization.get_domains():
            scan_history_id = create_scan_object(
                host_id=domain.id,
                engine_id=engine_id,
                initiated_by_id=request.user.id
            )
            scan = ScanHistory.objects.get(pk=scan_history_id)

            kwargs = {
                'scan_history_id': scan.id,
                'domain_id': domain.id,
                'engine_id': engine_id,
                'scan_type': LIVE_SCAN,
                'results_dir': settings.RENGINE_RESULTS,
                'initiated_by_id': request.user.id,
                'imported_subdomains': subdomains_in,
                'out_of_scope_subdomains': subdomains_out,
                'starting_point_path': starting_point_path,
                'excluded_paths': excluded_paths,
                'enable_spiderfoot_scan': 'spiderfoot_scan' in request.POST,
            }
            initiate_scan_temporal(**kwargs)
            scan.save()


        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request,
            messages.INFO,
            f'Scan Started for {ndomains} domains in organization {organization.name}')
        return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects.order_by('engine_name')
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    domain_list = organization.get_domains()
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)

    context = {
        'organization_data_active': 'true',
        'list_organization_li': 'active',
        'organization': organization,
        'engines': engine,
        'domain_list': domain_list,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_INITATE_SCANS_SUBSCANS, redirect_url=FOUR_OH_FOUR_URL)
def schedule_organization_scan(request, slug, id):
    organization =Organization.objects.get(id=id)
    if request.method == "POST":
        engine_type = int(request.POST['scan_mode'])
        engine = get_object_or_404(EngineType, id=engine_type)

        # post vars
        scheduled_mode = request.POST['scheduled_mode']
        subdomains_in = request.POST['importSubdomainTextArea'].split()
        subdomains_in = [s.rstrip() for s in subdomains_in if s]
        subdomains_out = request.POST['outOfScopeSubdomainTextarea'].split()
        subdomains_out = [s.rstrip() for s in subdomains_out if s]
        starting_point_path = request.POST['startingPointPath'].strip()
        excluded_paths = request.POST['excludedPaths'] # string separated by ,
        # split excluded paths by ,
        excluded_paths = [path.strip() for path in excluded_paths.split(',')]

        for domain in organization.get_domains():
            timestr = str(datetime.strftime(timezone.now(), '%Y_%m_%d_%H_%M_%S'))
            task_name = f'{engine.engine_name} for {domain.name}: {timestr}'

            from reNgine.definitions import SCHEDULED_SCAN, LIVE_SCAN
            from reNgine.temporal_schedule_utils import (
                _create_periodic_temporal_schedule,
                _create_clocked_temporal_schedule,
                interval_to_seconds,
            )
            # Period task
            if scheduled_mode == 'periodic':
                frequency_value = int(request.POST['frequency'])
                frequency_type = request.POST['frequency_type']
                _create_periodic_temporal_schedule(
                    name=task_name,
                    interval_seconds=interval_to_seconds(frequency_value, frequency_type),
                    workflow_args={
                        'domain_id': domain.id,
                        'engine_id': engine.id,
                        'scan_type': SCHEDULED_SCAN,
                        'initiated_by_id': request.user.id,
                        'imported_subdomains': subdomains_in,
                        'out_of_scope_subdomains': subdomains_out,
                        'starting_point_path': starting_point_path,
                        'excluded_paths': excluded_paths,
                        'enable_spiderfoot_scan': 'spiderfoot_scan' in request.POST,
                    },
                    domain_id=domain.id,
                )

            # Clocked task
            elif scheduled_mode == 'clocked':
                schedule_time = request.POST['scheduled_time']
                _create_clocked_temporal_schedule(
                    name=task_name,
                    clocked_time=schedule_time,
                    workflow_args={
                        'domain_id': domain.id,
                        'engine_id': engine.id,
                        'scan_type': LIVE_SCAN,
                        'initiated_by_id': request.user.id,
                        'imported_subdomains': subdomains_in,
                        'out_of_scope_subdomains': subdomains_out,
                        'starting_point_path': starting_point_path,
                        'excluded_paths': excluded_paths,
                        'enable_spiderfoot_scan': 'spiderfoot_scan' in request.POST,
                    },
                    domain_id=domain.id,
                )

        # Send start notif
        ndomains = len(organization.get_domains())
        messages.add_message(
            request,
            messages.INFO,
            f'Scan started for {ndomains} domains in organization {organization.name}'
        )
        return HttpResponseRedirect(reverse('scheduled_scan_view', kwargs={'slug': slug}))

    # GET request
    engine = EngineType.objects
    custom_engine_count = EngineType.objects.filter(default_engine=False).count()
    excluded_paths = ','.join(DEFAULT_EXCLUDED_PATHS)
    context = {
        'scan_history_active': 'active',
        'organization': organization,
        'domain_list': organization.get_domains(),
        'engines': engine,
        'custom_engine_count': custom_engine_count,
        'excluded_paths': excluded_paths
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_RESULTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_scans(request, slug):
    if request.method == "POST":
        for key, value in request.POST.items():
            if key == 'scan_history_table_length' or key == 'csrfmiddlewaretoken':
                continue
            scan = get_object_or_404(ScanHistory, id=value)
            delete_dir = scan.results_dir
            run_command('rm -rf ' + delete_dir, shell=True)
            scan.delete()
        messages.add_message(
            request,
            messages.INFO,
            'Multiple scans successfully deleted!')
    return HttpResponseRedirect(reverse('scan_history', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def customize_report(request, id):
    scan = ScanHistory.objects.get(id=id)
    context = {
        'scan_id': id,
        'scan_history': scan,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def update_leak_status(request, id):
    if request.method == 'POST':
        leak = get_object_or_404(SecretLeak, id=id)
        status = request.POST.get('status')
        if status in ['unverified', 'verified', 'false_positive']:
            leak.status = status
            leak.save()
            return JsonResponse({'status': True})
    return JsonResponse({'status': False})


def delete_leak(request, id):
    if request.method == 'POST':
        leak = get_object_or_404(SecretLeak, id=id)
        leak.delete()
        return JsonResponse({'status': True})
    return JsonResponse({'status': False})


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def create_report(request, id):
    """Initiate a report generation task.

    Args:
        request: The HTTP request object containing GET parameters:
            - report_type (str): Type of report (full, vulnerability).
            - report_template (str): Style template (default, modern, enterprise, cyber_pro).
            - ignore_info_vuln (str): Whether to ignore informational vulnerabilities ('True'/'False').
            - include_attack_surface_map (str): Whether to include the attack surface map ('True'/'False').
            - include_attack_paths (str): Whether to include the APME Attack Paths ('True'/'False').
            - comments (str): Optional assessment comments to insert in template.
        id (int): ScanHistory database ID.
    """
    report_type = request.GET.get('report_type', 'full')
    report_template = request.GET.get('report_template', 'default')
    is_ignore_info_vuln = request.GET.get('ignore_info_vuln', 'False') == 'True'
    include_attack_surface_map = request.GET.get('include_attack_surface_map', 'False') == 'True'
    include_attack_paths = request.GET.get('include_attack_paths', 'False') == 'True'
    # Default True for backward-compat — older callers that don't send this param
    # should still include parameters (preserving prior behaviour).
    include_found_parameters = request.GET.get('include_found_parameters', 'True') == 'True'
    include_secret_findings = request.GET.get('include_secret_findings', 'True') == 'True'
    comments = request.GET.get('comments', '')

    scan = get_object_or_404(ScanHistory, id=id)

    report_obj = ScanReport.objects.create(
        scan_history=scan,
        report_type=report_type,
        report_template=report_template,
        status=-1, # Initiated
        params={
            'ignore_info_vuln': is_ignore_info_vuln,
            'include_attack_surface_map': include_attack_surface_map,
            'include_attack_paths': include_attack_paths,
            'include_found_parameters': include_found_parameters,
            'include_secret_findings': include_secret_findings,
            'comments': comments
        }
    )

    from reNgine.tasks.report import generate_report_task
    threading.Thread(
        target=generate_report_task,
        args=(report_obj.id,),
        daemon=True
    ).start()

    return JsonResponse({'status': True, 'report_id': report_obj.id})


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def get_report_status(request, id):
    report = get_object_or_404(ScanReport, id=id)
    response = {
        'status': report.status,
        'error_message': report.error_message,
        'report_url': report.report_file.url if report.report_file else None,
        'completed_at': report.completed_at
    }
    return JsonResponse(response)

