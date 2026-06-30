import glob
import json
import os
import re
import shutil
import subprocess
import logging
import threading

logger = logging.getLogger(__name__)

from datetime import datetime
from django import http
from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from rolepermissions.decorators import has_permission_decorator

from reNgine.common_func import *
from reNgine.tasks import (run_command, send_discord_message, send_slack_message,send_lark_message, send_telegram_message, fetch_proxies_task)
from django.core.cache import cache
from reNgine.utils.llm import LLMModelManager
from dashboard.models import LLMConfig
from scanEngine.forms import *
from scanEngine.forms import ConfigurationForm
from scanEngine.models import *
from dashboard.models import SpiderfootAPIKey, LinkedInCredentials, HunterIOAPIKey, WpScanAPIKey, ProjectDiscoveryAPIKey


def index(request, slug):
    engine_type = EngineType.objects.order_by('engine_name').all()
    context = {
        'engine_ul_show': 'show',
        'engine_li': 'active',
        'scan_engine_nav_active': 'active',
        'engine_type': engine_type,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_engine(request, slug):
    form = AddEngineForm()
    if request.method == "POST":
        form = AddEngineForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Scan Engine Added successfully')
            return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))
    context = {
        'engine_nav_active': 'active',
        'add_engine_li': 'active',
        'engine_ul_show': 'show',
        'form': form,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def delete_engine(request, slug, id):
    obj = get_object_or_404(EngineType, id=id)
    if request.method == "POST":
        obj.delete()
        messages.add_message(
            request,
            messages.INFO,
            'Scan Engine Deleted successfully')
    return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_engine(request, slug, id):
    obj = get_object_or_404(EngineType, id=id)
    form = AddEngineForm(instance=obj)
    if request.method == "POST":
        form = AddEngineForm(request.POST, instance=obj)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Scan Engine Updated successfully')
            return http.HttpResponseRedirect(reverse('scan_engine_index', kwargs={'slug': slug}))
    context = {
        'engine_nav_active': 'active',
        'engine_ul_show': 'show',
        'form': form,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def wordlist_list(request, slug):
    wordlists = Wordlist.objects.all()
    context = {
        'settings_nav_active': 'active',
        'wordlist_li': 'active',
        'settings_ul_show': 'show',
        'wordlists': wordlists,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def add_wordlist(request, slug):
    form = WordlistForm()
    if request.method == "POST":
        form = WordlistForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Wordlist Added successfully')
            return http.HttpResponseRedirect(reverse('wordlist_list', kwargs={'slug': slug}))
    context = {
        'settings_nav_active': 'active',
        'wordlist_li': 'active',
        'settings_ul_show': 'show',
        'form': form,
    }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_WORDLISTS, redirect_url=FOUR_OH_FOUR_URL)
def delete_wordlist(request, slug, id):
    obj = get_object_or_404(Wordlist, id=id)
    if request.method == "POST":
        obj.delete()
        messages.add_message(
            request,
            messages.INFO,
            'Wordlist Deleted successfully')
    return http.HttpResponseRedirect(reverse('wordlist_list', kwargs={'slug': slug}))


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def interesting_lookup(request, slug):
    context = {}
    form = InterestingLookupForm()
    lookup_keywords = None
    if InterestingLookupModel.objects.filter(id=1).exists():
        lookup_keywords = InterestingLookupModel.objects.get(id=1)
        form.set_value(lookup_keywords)
    else:
        form.set_initial()

    if request.method == "POST":
        if lookup_keywords:
            form = InterestingLookupForm(request.POST, instance=lookup_keywords)
        else:
            form = InterestingLookupForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Lookup Keywords updated successfully')
            return http.HttpResponseRedirect(reverse('interesting_lookup', kwargs={'slug': slug}))

    if lookup_keywords:
        form.set_value(lookup_keywords)
        context['interesting_lookup_found'] = True
    context['form'] = form
    context['default_lookup'] = InterestingLookupModel.objects.filter(id=1)
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_specific_settings(request, slug):
    context = {}
    # check for incoming form requests
    if request.method == "POST":

        if 'gfFileUpload[]' in request.FILES:
            gf_files = request.FILES.getlist('gfFileUpload[]')
            upload_count = 0
            for gf_file in gf_files:
                original_filename = gf_file.name if isinstance(gf_file.name, str) else gf_file.name.decode('utf-8')
                # remove special chars from filename, that could possibly do directory traversal or XSS
                original_filename = re.sub(r'[\\/*?:"<>|]',"", original_filename)
                file_extension = original_filename.split('.')[len(gf_file.name.split('.'))-1]
                if file_extension == 'json':
                    base_filename = os.path.splitext(original_filename)[0]
                    file_path = '/root/.gf/' + base_filename + '.json'
                    file = open(file_path, "w")
                    file.write(gf_file.read().decode("utf-8"))
                    file.close()
                    upload_count += 1
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': f'{upload_count} GF files successfully uploaded'})
            messages.add_message(request, messages.INFO, f'{upload_count} GF files successfully uploaded')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'nucleiFileUpload[]' in request.FILES:
            nuclei_files = request.FILES.getlist('nucleiFileUpload[]')
            upload_count = 0
            for nuclei_file in nuclei_files:
                original_filename = nuclei_file.name if isinstance(nuclei_file.name, str) else nuclei_file.name.decode('utf-8')
                original_filename = re.sub(r'[\\/*?:"<>|]',"", original_filename)
                file_extension = original_filename.split('.')[len(nuclei_file.name.split('.'))-1]
                if file_extension in ['yaml', 'yml']:
                    base_filename = os.path.splitext(original_filename)[0]
                    file_path = '/root/nuclei-templates/' + base_filename + '.yaml'
                    file = open(file_path, "w")
                    file.write(nuclei_file.read().decode("utf-8"))
                    file.close()
                    upload_count += 1
            if request.headers.get('Accept') == 'application/json':
                if upload_count == 0:
                     return http.JsonResponse({'status': 'error', 'message': 'Invalid Nuclei Pattern, upload only *.yaml extension'}, status=400)
                return http.JsonResponse({'status': 'success', 'message': f'{upload_count} Nuclei Patterns successfully uploaded'})
            if upload_count == 0:
                messages.add_message(request, messages.ERROR, 'Invalid Nuclei Pattern, upload only *.yaml extension')
            messages.add_message(request, messages.INFO, f'{upload_count} Nuclei Patterns successfully uploaded')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'nuclei_config_text_area' in request.POST:
            with open('/root/.config/nuclei/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('nuclei_config_text_area'))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'Nuclei config updated!'})
            messages.add_message(request, messages.INFO, 'Nuclei config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'subfinder_config_text_area' in request.POST:
            with open('/root/.config/subfinder/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('subfinder_config_text_area'))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'Subfinder config updated!'})
            messages.add_message(request, messages.INFO, 'Subfinder config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'naabu_config_text_area' in request.POST:
            with open('/root/.config/naabu/config.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('naabu_config_text_area'))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'Naabu config updated!'})
            messages.add_message(request, messages.INFO, 'Naabu config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'amass_config_text_area' in request.POST:
            with open('/root/.config/amass.ini', "w") as fhandle:
                fhandle.write(request.POST.get('amass_config_text_area'))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'Amass config updated!'})
            messages.add_message(request, messages.INFO, 'Amass config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'theharvester_config_text_area' in request.POST:
            with open('/usr/src/github/theHarvester/api-keys.yaml', "w") as fhandle:
                fhandle.write(request.POST.get('theharvester_config_text_area'))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'theHarvester config updated!'})
            messages.add_message(request, messages.INFO, 'theHarvester config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

        elif 'spiderfoot_config_text_area' in request.POST:
            # Use /usr/src/github/spiderfoot/spiderfoot.cfg as persistent config
            sf_config_path = '/usr/src/github/spiderfoot/spiderfoot.cfg'
            os.makedirs(os.path.dirname(sf_config_path), exist_ok=True)
            with open(sf_config_path, "w") as fhandle:
                fhandle.write(request.POST.get('spiderfoot_config_text_area'))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'SpiderFoot config updated!'})
            messages.add_message(request, messages.INFO, 'SpiderFoot config updated!')
            return http.HttpResponseRedirect(reverse('tool_settings', kwargs={'slug': slug}))

    gf_list = []
    try:
        gf_list = (subprocess.check_output(['gf', '-list'])).decode("utf-8").split('\n')
    except:
        pass
    _tpl_base = "/root/nuclei-templates"
    nuclei_custom_pattern = sorted(
        os.path.relpath(f, _tpl_base)
        for f in glob.glob(f"{_tpl_base}/**/*.yaml", recursive=True)
                 + glob.glob(f"{_tpl_base}/**/*.yml", recursive=True)
    )

    if request.headers.get('Accept') == 'application/json':
        return http.JsonResponse({
            'gf_patterns': sorted([p for p in gf_list if p]),
            'nuclei_templates': nuclei_custom_pattern
        })

    context['settings_nav_active'] = 'active'
    context['tool_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    context['nuclei_templates'] = nuclei_custom_pattern
    context['gf_patterns'] = sorted([p for p in gf_list if p])
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def rengine_settings(request, slug):
    context = {}

    total, used, _ = shutil.disk_usage("/")
    total = total // (2**30)
    used = used // (2**30)
    context['total'] = total
    context['used'] = used
    context['free'] = total-used
    context['consumed_percent'] = int(100 * float(used)/float(total))

    context['settings_nav_active'] = 'active'
    context['rengine_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def notification_settings(request, slug):
    context = {}
    form = NotificationForm()
    notification = None
    if Notification.objects.all().exists():
        notification = Notification.objects.all()[0]
        form.set_value(notification)
    else:
        form.set_initial()

    if request.method == "POST":
        if notification:
            form = NotificationForm(request.POST, instance=notification)
        else:
            form = NotificationForm(request.POST or None)

        if form.is_valid():
            form.save()
            send_slack_message('*reNgine*\nCongratulations! your notification services are working.')
            send_lark_message('*reNgine*\nCongratulations! your notification services are working.')
            send_telegram_message('*reNgine*\nCongratulations! your notification services are working.')
            send_discord_message('**reNgine**\nCongratulations! your notification services are working.')
            messages.add_message(
                request,
                messages.INFO,
                'Notification Settings updated successfully and test message was sent.')
            return http.HttpResponseRedirect(reverse('notification_settings', kwargs={'slug': slug}))

    context['settings_nav_active'] = 'active'
    context['notification_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    context['form'] = form

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def proxy_settings(request, slug):
    context = {}
    form = ProxyForm()
    context['form'] = form

    proxy = None
    if Proxy.objects.all().exists():
        proxy = Proxy.objects.all()[0]
        form.set_value(proxy)
    else:
        form.set_initial()

    if request.method == "POST":
        old_use_tor = proxy.use_tor if proxy else False
        skip_validation = str(request.POST.get('skip_validation', '')).lower() == 'true'
        if proxy:
            form = ProxyForm(request.POST, instance=proxy)
        else:
            form = ProxyForm(request.POST or None)

        if form.is_valid():
            proxy_instance = form.save(commit=False)
            if proxy_instance.use_proxy and proxy_instance.proxies and not skip_validation:
                from reNgine.common_func import validate_proxies
                original_count = len([line for line in proxy_instance.proxies.splitlines() if line.strip()])
                validated = validate_proxies(proxy_instance.proxies)
                proxy_instance.proxies = validated
                saved_count = len([line for line in validated.splitlines() if line.strip()])
                message = f'Proxies updated. Validated {saved_count}/{original_count} live proxies.'
            elif proxy_instance.use_proxy and proxy_instance.proxies and skip_validation:
                message = 'Proxies updated without server-side validation.'
            else:
                message = 'Proxies updated.'
            proxy_instance.save()
            # TOR container lifecycle — start or stop on change
            new_use_tor = proxy_instance.use_tor
            if new_use_tor != old_use_tor:
                from reNgine.tor_manager import TorManager, TorStartError, TorUnavailableError
                tor = TorManager()
                try:
                    if new_use_tor:
                        tor.start()
                    else:
                        tor.stop()
                except TorStartError as e:
                    proxy_instance.use_tor = False
                    proxy_instance.save(update_fields=['use_tor'])
                    err_msg = f'TOR failed to start: {e}'
                    if request.headers.get('Accept') == 'application/json':
                        return http.JsonResponse({'status': 'error', 'message': err_msg}, status=500)
                    messages.add_message(request, messages.ERROR, err_msg)
                    return http.HttpResponseRedirect(reverse('proxy_settings', kwargs={'slug': slug}))
                except TorUnavailableError as e:
                    proxy_instance.use_tor = False
                    proxy_instance.save(update_fields=['use_tor'])
                    err_msg = f'Docker socket not available: {e}'
                    if request.headers.get('Accept') == 'application/json':
                        return http.JsonResponse({'status': 'error', 'message': err_msg}, status=503)
                    messages.add_message(request, messages.ERROR, err_msg)
                    return http.HttpResponseRedirect(reverse('proxy_settings', kwargs={'slug': slug}))
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': message})
            messages.add_message(
                request,
                messages.INFO,
                message)
            return http.HttpResponseRedirect(reverse('proxy_settings', kwargs={'slug': slug}))
        else:
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'error', 'errors': form.errors}, status=400)

    if request.headers.get('Accept') == 'application/json':
        return http.JsonResponse({
            'use_proxy': proxy.use_proxy if proxy else False,
            'proxies': proxy.proxies if proxy else "",
            'use_proxychains': proxy.use_proxychains if proxy else False,
            'use_tor': proxy.use_tor if proxy else False,
        })

    context['settings_nav_active'] = 'active'
    context['proxy_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def opsec_settings(request, slug):
    context = {}
    form = OpSecForm()
    context['form'] = form

    opsec = None
    if OpSec.objects.all().exists():
        opsec = OpSec.objects.all()[0]
        form.set_value(opsec)
    else:
        form.set_initial()

    if request.method == "POST":
        if opsec:
            form = OpSecForm(request.POST, instance=opsec)
        else:
            form = OpSecForm(request.POST or None)

        if form.is_valid():
            form.save()
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'OpSec Settings updated.'})
            messages.add_message(
                request,
                messages.INFO,
                'OpSec Settings updated.')
            return http.HttpResponseRedirect(reverse('opsec_settings', kwargs={'slug': slug}))
        else:
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'error', 'errors': form.errors}, status=400)

    if request.headers.get('Accept') == 'application/json':
        return http.JsonResponse({
            'enable_opsec': opsec.enable_opsec if opsec else False,
            'enable_random_ua': opsec.enable_random_ua if opsec else False,
            'enable_waf_bypass': opsec.enable_waf_bypass if opsec else False,
            'enable_ja3_randomization': opsec.enable_ja3_randomization if opsec else False,
            'enable_rate_limit': opsec.enable_rate_limit if opsec else False,
            'max_rps': opsec.max_rps if opsec else 10,
            'enable_delay': opsec.enable_delay if opsec else False,
            'delay_ms': opsec.delay_ms if opsec else 0,
            'enable_jitter': opsec.enable_jitter if opsec else False,
            'jitter_percent': opsec.jitter_percent if opsec else 0,
            'http_protocol': opsec.http_protocol if opsec else "http1.1",
            'custom_dns_servers': opsec.custom_dns_servers if opsec else "",
            'enable_metadata_stripping': opsec.enable_metadata_stripping if opsec else False,
        })

    context['settings_nav_active'] = 'active'
    context['opsec_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def test_hackerone(request, slug):
    if request.method == "POST":
        headers = {
            'Accept': 'application/json'
        }
        body = json.loads(request.body)
        r = requests.get(
            'https://api.hackerone.com/v1/hackers/payments/balance',
            auth=(body['username'], body['api_key']),
            headers = headers
        )
        if r.status_code == 200:
            return http.JsonResponse({"status": 200})

    return http.JsonResponse({"status": 401})


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def hackerone_settings(request, slug):
    context = {}
    form = HackeroneForm()
    context['form'] = form

    hackerone = None
    if Hackerone.objects.all().exists():
        hackerone = Hackerone.objects.all()[0]
        form.set_value(hackerone)
    else:
        form.set_initial()

    if request.method == "POST":
        if hackerone:
            form = HackeroneForm(request.POST, instance=hackerone)
        else:
            form = HackeroneForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Hackerone Settings updated.')
            return http.HttpResponseRedirect(reverse('hackerone_settings', kwargs={'slug': slug}))
    context['settings_nav_active'] = 'active'
    context['hackerone_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_REPORT, redirect_url=FOUR_OH_FOUR_URL)
def report_settings(request, slug):
    context = {}
    form = ReportForm()
    context['form'] = form

    primary_color = '#FFB74D'
    secondary_color = '#212121'

    report = None
    if VulnerabilityReportSetting.objects.all().exists():
        report = VulnerabilityReportSetting.objects.all()[0]
        primary_color = report.primary_color
        secondary_color = report.secondary_color
        form.set_value(report)
    else:
        form.set_initial()

    if request.method == "POST":
        if report:
            form = ReportForm(request.POST, instance=report)
        else:
            form = ReportForm(request.POST or None)

        if form.is_valid():
            form.save()
            messages.add_message(
                request,
                messages.INFO,
                'Report Settings updated.')
            return http.HttpResponseRedirect(reverse('report_settings', kwargs={'slug': slug}))


    context['settings_nav_active'] = 'active'
    context['report_settings_li'] = 'active'
    context['settings_ul_show'] = 'show'
    context['primary_color'] = primary_color
    context['secondary_color'] = secondary_color
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def fetch_proxies(request, slug):
    if request.method == "POST":
        try:
            limit = 1000
            try:
                import json
                body = json.loads(request.body)
                if 'limit' in body:
                    limit = int(body['limit'])
            except Exception:
                if 'limit' in request.POST:
                    limit = int(request.POST.get('limit'))
            from reNgine.job_tracker import create_job
            import threading
            job_id = create_job()
            threading.Thread(
                target=fetch_proxies_task,
                kwargs={'limit': limit, 'job_id': job_id},
                daemon=True,
            ).start()
            return http.JsonResponse({'task_id': job_id})
        except Exception as e:
            return http.JsonResponse({'error': str(e)}, status=500)
    return http.JsonResponse({'error': 'Invalid request method. POST required.'}, status=405)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def get_proxy_task_status(request, slug, task_id):
    from reNgine.job_tracker import get_job
    job = get_job(task_id)
    result = {
        "task_id": task_id,
        "status": job.get("status", "UNKNOWN"),
        "result": job.get("result") if job.get("status") == "SUCCESS" else None,
    }
    if job.get("status") in ("RUNNING", "SUCCESS"):
        result["message"] = job.get("message", "")
        result["progress"] = job.get("progress", 0)
    return http.JsonResponse(result)


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def check_proxy_single(request, slug):
    """Validate a single proxy URL. POST {proxy: str} → {proxy: str, valid: bool}"""
    if request.method != 'POST':
        return http.JsonResponse({'error': 'Method not allowed'}, status=405)
    import json as _json
    try:
        body = _json.loads(request.body)
    except (_json.JSONDecodeError, ValueError):
        return http.JsonResponse({'error': 'Invalid JSON'}, status=400)
    proxy_url = (body.get('proxy') or '').strip()
    if not proxy_url:
        return http.JsonResponse({'error': 'No proxy provided'}, status=400)
    from reNgine.common_func import check_proxy_robust
    is_valid = check_proxy_robust(proxy_url)
    return http.JsonResponse({'proxy': proxy_url, 'valid': bool(is_valid)})


@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def check_proxy_bulk(request, slug):
    """Validate multiple proxy URLs concurrently. POST {proxies: list} → {results: dict}"""
    if request.method != 'POST':
        return http.JsonResponse({'error': 'Method not allowed'}, status=405)
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return http.JsonResponse({'error': 'Invalid JSON'}, status=400)
    proxies = body.get('proxies', [])
    if not isinstance(proxies, list):
        return http.JsonResponse({'error': 'No proxies list provided'}, status=400)

    # Prevent potential resource exhaustion by capping target list
    proxies = proxies[:500]

    from reNgine.common_func import check_proxy_robust, PROXY_VALIDATION_TIMEOUT, PROXY_VALIDATION_MAX_WORKERS
    from concurrent.futures import ThreadPoolExecutor, as_completed

    max_workers = min(PROXY_VALIDATION_MAX_WORKERS, max(1, len(proxies)))
    results = {}

    # Each proxy URL is used as the outbound proxy for external IP-check requests.
    # SSRF surface: only authenticated users with PERM_MODIFY_SCAN_CONFIGURATIONS can
    # reach this endpoint (enforced by @has_permission_decorator above).
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {
            executor.submit(check_proxy_robust, p, PROXY_VALIDATION_TIMEOUT): p 
            for p in proxies if p.strip()
        }
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                is_valid = future.result()
            except Exception:
                is_valid = False
            results[proxy] = bool(is_valid)

    return http.JsonResponse({'results': results})


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def tool_arsenal_section(request, slug):
    tools = InstalledExternalTool.objects.all().order_by('id')
    
    if request.headers.get('Accept') == 'application/json':
        tools_list = []
        for tool in tools:
            tools_list.append({
                'id': tool.id,
                'name': tool.name,
                'description': tool.description,
                'logo_url': tool.logo_url,
                'github_url': tool.github_url,
                'license_url': tool.license_url,
                'is_default': tool.is_default,
                'is_subdomain_gathering': tool.is_subdomain_gathering,
                'is_github_cloned': tool.is_github_cloned,
                'github_clone_path': tool.github_clone_path,
                'install_command': tool.install_command,
                'update_command': tool.update_command,
                'version_lookup_command': tool.version_lookup_command,
            })
        return http.JsonResponse({'status': 'success', 'tools': tools_list})

    context = {}
    context['installed_tools'] = tools
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def llm_toolkit_section(request, slug):
    context = {
        'settings_nav_active': 'active',
        'llm_toolkit_nav_active': 'active',
        'slug': slug
    }
    # Sync OpenAI from vault if LLMConfig doesn't have it
    from dashboard.models import OpenAiAPIKey
    from reNgine.definitions import OPENAI
    openai_vault = OpenAiAPIKey.objects.first()
    if openai_vault:
        openai_config, created = LLMConfig.objects.get_or_create(provider=OPENAI)
        if not openai_config.api_key:
            openai_config.api_key = openai_vault.key
            openai_config.save()

    # Get all LLM configs
    configs = LLMConfig.objects.all()
    context['llm_configs'] = configs
    
    # Identify active provider for default selection
    active_config = configs.filter(is_active=True).first()
    context['active_provider'] = active_config.provider if active_config else 'ollama'
    context['active_config'] = active_config
    
    if request.headers.get('Accept') == 'application/json':
        return http.JsonResponse({
            'llm_configs': [
                {
                    'provider': c.provider,
                    'api_key': c.api_key,
                    'selected_model': c.selected_model,
                    'is_active': c.is_active
                } for c in configs
            ],
            'active_provider': context['active_provider']
        })

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_llm_settings(request, slug):
    if request.method == "POST":
        provider = request.POST.get('provider')
        api_key = request.POST.get('api_key')
        selected_model = request.POST.get('selected_model')
        is_active = request.POST.get('is_active') == 'true'
        action = request.POST.get('action') # 'save' or 'pull'
        
        config, created = LLMConfig.objects.get_or_create(provider=provider)
        config.api_key = api_key
        config.selected_model = selected_model
        
        if is_active:
            # Deactivate others
            LLMConfig.objects.exclude(id=config.id).update(is_active=False)
            config.is_active = True
        
        config.save()
        
        if action == 'pull' and provider == 'ollama':
            from reNgine.tasks import pull_ollama_model
            threading.Thread(target=pull_ollama_model, args=(selected_model,), daemon=True).start()
            return http.JsonResponse({'status': 'pulling', 'message': f'Started pulling {selected_model}'})
            
        return http.JsonResponse({'status': 'success', 'message': 'Settings updated successfully'})
    return http.JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def fetch_llm_models(request, slug):
    provider = request.GET.get('provider')
    api_key = request.GET.get('api_key')
    
    manager = LLMModelManager()
    models = manager.get_models(provider, api_key)
    
    return http.JsonResponse({'status': 'success', 'models': models})

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def get_ollama_pull_status(request, slug):
    model_name = request.GET.get('model')
    log = cache.get(f"ollama_pull_log_{model_name}", "Waiting for logs...")
    status = cache.get(f"ollama_pull_status_{model_name}", "running")
    
    return http.JsonResponse({
        'status': status,
        'log': log
    })

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def get_ollama_service_status(request, slug):
    from reNgine.ollama_manager import OllamaManager, OllamaUnavailableError
    manager = OllamaManager()
    is_running = manager.is_running()
    return http.JsonResponse({'status': 'success', 'running': is_running})

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def start_ollama_service(request, slug):
    if request.method != 'POST':
        return http.JsonResponse({'status': 'error', 'message': 'POST required'}, status=400)
    
    from reNgine.ollama_manager import OllamaManager, OllamaStartError
    manager = OllamaManager()
    try:
        manager.start()
        return http.JsonResponse({'status': 'success', 'message': 'Ollama service started.'})
    except OllamaStartError as e:
        return http.JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def stop_ollama_service(request, slug):
    if request.method != 'POST':
        return http.JsonResponse({'status': 'error', 'message': 'POST required'}, status=400)
    
    from reNgine.ollama_manager import OllamaManager
    manager = OllamaManager()
    manager.stop()
    return http.JsonResponse({'status': 'success', 'message': 'Ollama service stopped.'})


def _test_llm_provider(provider: str, api_key: str, model: str) -> dict:
    """Send a minimal prompt to the given provider and return a result dict.

    Returns {'status': 'success'|'error', 'message': str, 'response': str}.
    Never raises; all exceptions are caught and converted to error results.
    """
    import requests as req_lib
    from urllib.parse import urlparse
    from reNgine.definitions import OLLAMA, OPENAI, ANTHROPIC, GEMINI, OLLAMA_INSTANCE

    TEST_SYSTEM = "You are a connectivity test assistant."
    TEST_PROMPT = "Reply with exactly the word: CONNECTED"

    _HTTP_ERROR_HINTS = {
        401: "Invalid API key — please check your credentials.",
        402: "Payment required — your account may have no remaining credits or needs a billing update.",
        403: "Access forbidden — your API key may lack the required permissions.",
        429: "Rate limit or quota exceeded — please check your plan limits or try again later.",
    }

    def _parse_http_error(exc) -> str:
        try:
            code = exc.response.status_code
            hint = _HTTP_ERROR_HINTS.get(code)
            if hint:
                return hint
            try:
                body = exc.response.json()
                msg = (
                    (body.get('error') or {}).get('message')
                    or body.get('message')
                    or f"HTTP {code} from provider."
                )
                return f"Provider error ({code}): {msg}"
            except Exception:
                return f"HTTP {code} from provider."
        except Exception:
            return "Unexpected HTTP error from provider."

    if provider == OLLAMA:
        host = api_key or OLLAMA_INSTANCE
        parsed = urlparse(host)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            return {'status': 'error', 'message': 'Invalid Ollama host URL — must use http:// or https://.', 'response': ''}
        try:
            tags_resp = req_lib.get(f"{host}/api/tags", timeout=10)
            tags_resp.raise_for_status()
            use_model = model
            if not use_model:
                tags = tags_resp.json().get('models', [])
                use_model = tags[0]['name'] if tags else 'llama3'
            gen_resp = req_lib.post(
                f"{host}/api/generate",
                json={"model": use_model, "prompt": TEST_PROMPT, "stream": False},
                timeout=60,
            )
            gen_resp.raise_for_status()
            response_text = gen_resp.json().get('response', '').strip()
            return {'status': 'success', 'message': 'Ollama connection successful.', 'response': response_text}
        except req_lib.exceptions.ConnectionError:
            return {'status': 'error', 'message': f"Cannot reach Ollama at {host} — is the service running?", 'response': ''}
        except req_lib.exceptions.Timeout:
            return {'status': 'error', 'message': 'Connection to Ollama timed out.', 'response': ''}
        except req_lib.exceptions.HTTPError as exc:
            return {'status': 'error', 'message': _parse_http_error(exc), 'response': ''}
        except Exception:
            logger.exception("Unexpected error during Ollama connection test")
            return {'status': 'error', 'message': 'Unexpected error during Ollama connection test.', 'response': ''}

    elif provider == OPENAI:
        if not api_key:
            return {'status': 'error', 'message': 'OpenAI API key is required.', 'response': ''}
        use_model = model or 'gpt-3.5-turbo'
        try:
            resp = req_lib.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": use_model,
                    "messages": [
                        {"role": "system", "content": TEST_SYSTEM},
                        {"role": "user", "content": TEST_PROMPT},
                    ],
                    "max_tokens": 20,
                },
                timeout=30,
            )
            resp.raise_for_status()
            response_text = resp.json()['choices'][0]['message']['content'].strip()
            return {'status': 'success', 'message': 'OpenAI connection successful.', 'response': response_text}
        except req_lib.exceptions.HTTPError as exc:
            return {'status': 'error', 'message': _parse_http_error(exc), 'response': ''}
        except req_lib.exceptions.Timeout:
            return {'status': 'error', 'message': 'OpenAI request timed out.', 'response': ''}
        except Exception:
            logger.exception("Unexpected error during OpenAI connection test")
            return {'status': 'error', 'message': 'Unexpected error during OpenAI connection test.', 'response': ''}

    elif provider == ANTHROPIC:
        if not api_key:
            return {'status': 'error', 'message': 'Anthropic API key is required.', 'response': ''}
        use_model = model or 'claude-3-haiku-20240307'
        try:
            resp = req_lib.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": use_model,
                    "max_tokens": 20,
                    "system": TEST_SYSTEM,
                    "messages": [{"role": "user", "content": TEST_PROMPT}],
                },
                timeout=30,
            )
            resp.raise_for_status()
            block = resp.json()['content'][0]
            if block.get('type') != 'text':
                return {'status': 'error', 'message': f"Unexpected response type from Anthropic: {block.get('type')}", 'response': ''}
            return {'status': 'success', 'message': 'Anthropic connection successful.', 'response': block['text'].strip()}
        except req_lib.exceptions.HTTPError as exc:
            return {'status': 'error', 'message': _parse_http_error(exc), 'response': ''}
        except req_lib.exceptions.Timeout:
            return {'status': 'error', 'message': 'Anthropic request timed out.', 'response': ''}
        except Exception:
            logger.exception("Unexpected error during Anthropic connection test")
            return {'status': 'error', 'message': 'Unexpected error during Anthropic connection test.', 'response': ''}

    elif provider == GEMINI:
        if not api_key:
            return {'status': 'error', 'message': 'Google Gemini API key is required.', 'response': ''}
        use_model = model or 'gemini-1.5-flash'
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{use_model}:generateContent"
            resp = req_lib.post(
                url,
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": f"{TEST_SYSTEM}\n\n{TEST_PROMPT}"}]}]},
                timeout=30,
            )
            resp.raise_for_status()
            response_text = resp.json()['candidates'][0]['content']['parts'][0]['text'].strip()
            return {'status': 'success', 'message': 'Gemini connection successful.', 'response': response_text}
        except req_lib.exceptions.HTTPError as exc:
            return {'status': 'error', 'message': _parse_http_error(exc), 'response': ''}
        except req_lib.exceptions.Timeout:
            return {'status': 'error', 'message': 'Gemini request timed out.', 'response': ''}
        except Exception:
            logger.exception("Unexpected error during Gemini connection test")
            return {'status': 'error', 'message': 'Unexpected error during Gemini connection test.', 'response': ''}

    return {'status': 'error', 'message': f"Unknown provider: {provider}", 'response': ''}


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def test_llm_connection(request, slug):
    if request.method != 'POST':
        return http.JsonResponse({'status': 'error', 'message': 'POST required'}, status=400)

    provider = request.POST.get('provider', '').strip()
    api_key = request.POST.get('api_key', '').strip()
    model = request.POST.get('model', '').strip()

    if not provider:
        return http.JsonResponse({'status': 'error', 'message': 'Provider is required.'}, status=400)

    result = _test_llm_provider(provider, api_key, model)
    status_code = 200 if result['status'] == 'success' else 400
    return http.JsonResponse(result, status=status_code)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def api_vault(request, slug):
    logger.info(f"api_vault view hit! Method: {request.method}, Slug: {slug}, User: {request.user}")
    context = {}
    if request.method == "POST":
        
        # Support both legacy FormData keys (key_netlas, key_acunetix_url, ...)
        # and JSON payload keys (netlas_key, acunetix_url, ...).
        json_payload = None
        try:
            content_type = (request.META.get("CONTENT_TYPE") or "").lower()
            if "application/json" in content_type:
                import json as _json
                raw = (request.body or b"").decode("utf-8", errors="ignore").strip()
                if raw:
                    json_payload = _json.loads(raw)
        except Exception:
            json_payload = None

        def _pick(*names):
            for n in names:
                if json_payload is not None and isinstance(json_payload, dict) and n in json_payload:
                    return json_payload.get(n)
                if n in request.POST:
                    return request.POST.get(n)
            return None

        key_openai = request.POST.get('key_openai')
        key_netlas = _pick('key_netlas', 'netlas_key')
        key_chaos = _pick('key_chaos', 'chaos_key')
        key_hackerone = _pick('key_hackerone', 'hackerone_key')
        username_hackerone = _pick('username_hackerone', 'hackerone_username')
        key_shodan = _pick('key_shodan', 'shodan_key')
        key_censys = _pick('key_censys', 'censys_key')
        key_acunetix_url = _pick('key_acunetix_url', 'acunetix_url')
        key_acunetix_key = _pick('key_acunetix_key', 'acunetix_key')
        key_hunterio = _pick('key_hunterio', 'hunterio_key')
        linkedin_username = _pick('linkedin_username', 'linkedin_username')
        key_wpscan = _pick('key_wpscan', 'wpscan_key')
        key_projectdiscovery = _pick('key_projectdiscovery', 'projectdiscovery_key')

        # Treat empty strings as "clear value" (fixes: unsetting defaults to last value).
        if key_openai is not None:
            openai_api_key = OpenAiAPIKey.objects.first()
            if openai_api_key:
                openai_api_key.key = key_openai
                openai_api_key.save()
            else:
                OpenAiAPIKey.objects.create(key=key_openai)

        if key_netlas is not None:
            netlas_api_key = NetlasAPIKey.objects.first()
            if netlas_api_key:
                netlas_api_key.key = key_netlas
                netlas_api_key.save()
            else:
                NetlasAPIKey.objects.create(key=key_netlas)

        if key_chaos is not None:
            chaos_api_key = ChaosAPIKey.objects.first()
            if chaos_api_key:
                chaos_api_key.key = key_chaos
                chaos_api_key.save()
            else:
                ChaosAPIKey.objects.create(key=key_chaos)

        if (key_hackerone is not None) or (username_hackerone is not None):
            hackerone_api_key = HackerOneAPIKey.objects.first()
            if hackerone_api_key:
                if username_hackerone is not None:
                    hackerone_api_key.username = username_hackerone
                if key_hackerone is not None:
                    hackerone_api_key.key = key_hackerone
                hackerone_api_key.save()
            else:
                HackerOneAPIKey.objects.create(
                    username=username_hackerone or "",
                    key=key_hackerone or ""
                )

        if key_shodan is not None:
            shodan_api_key = ShodanAPIKey.objects.first()
            if shodan_api_key:
                shodan_api_key.key = key_shodan
                shodan_api_key.save()
            else:
                ShodanAPIKey.objects.create(key=key_shodan)

        if key_censys is not None:
            censys_api_key = CensysAPIKey.objects.first()
            if censys_api_key:
                censys_api_key.api_key = key_censys
                censys_api_key.save()
            else:
                CensysAPIKey.objects.create(
                    api_key=key_censys
                )

        key_leaklookup = request.POST.get('key_leaklookup')
        if key_leaklookup is not None:
            leaklookup_key = LeakLookupAPIKey.objects.first()
            if leaklookup_key:
                leaklookup_key.key = key_leaklookup
                leaklookup_key.save()
            else:
                LeakLookupAPIKey.objects.create(key=key_leaklookup)

        spiderfoot_module = request.POST.get('spiderfoot_module')
        spiderfoot_key = request.POST.get('spiderfoot_key')
        if spiderfoot_module and spiderfoot_key:
            SpiderfootAPIKey.objects.update_or_create(
                module_name=spiderfoot_module,
                defaults={'key_value': spiderfoot_key}
            )

        if (key_acunetix_url is not None) or (key_acunetix_key is not None):
            # Update even when blank to allow clearing values.
            AcunetixAPIKey.objects.update_or_create(
                id=1,
                defaults={
                    'server_url': key_acunetix_url or "",
                    'api_key': key_acunetix_key or ""
                }
            )

        if key_hunterio is not None:
            HunterIOAPIKey.objects.update_or_create(
                id=1,
                defaults={'key': key_hunterio or ""}
            )

        if key_wpscan is not None:
            WpScanAPIKey.objects.update_or_create(
                id=1,
                defaults={'key': key_wpscan or ""}
            )

        if key_projectdiscovery is not None:
            ProjectDiscoveryAPIKey.objects.update_or_create(
                id=1,
                defaults={'key': key_projectdiscovery or ""}
            )

        if linkedin_username is not None:
            LinkedInCredentials.objects.update_or_create(
                id=1,
                defaults={'username': linkedin_username or ""}
            )

        delete_sf_key = request.POST.get('delete_sf_key')
        if delete_sf_key:
            SpiderfootAPIKey.objects.filter(id=delete_sf_key).delete()
        if request.headers.get('Accept') == 'application/json':
            return http.JsonResponse({'status': 'success', 'message': 'API Vault updated successfully'})

    openai_key = OpenAiAPIKey.objects.first()
    netlas_key = NetlasAPIKey.objects.first()
    chaos_key = ChaosAPIKey.objects.first()
    shodan_key = ShodanAPIKey.objects.first()
    censys_key = CensysAPIKey.objects.first()
    h1_key = HackerOneAPIKey.objects.first()
    if h1_key:
        hackerone_key = h1_key.key
        hackerone_username = h1_key.username
    else:
        hackerone_key = None
        hackerone_username = None

    context['openai_key'] = openai_key
    context['netlas_key'] = netlas_key
    context['chaos_key'] = chaos_key
    context['hackerone_key'] = hackerone_key
    context['hackerone_username'] = hackerone_username
    context['shodan_key'] = shodan_key
    context['censys_key'] = censys_key
    context['leaklookup_key'] = LeakLookupAPIKey.objects.first()
    context['acunetix_key'] = AcunetixAPIKey.objects.first()
    context['spiderfoot_keys'] = SpiderfootAPIKey.objects.all()
    
    if request.headers.get('Accept') == 'application/json':
        return http.JsonResponse({
            'netlas_key': netlas_key.key if netlas_key else "",
            'chaos_key': chaos_key.key if chaos_key else "",
            'shodan_key': shodan_key.key if shodan_key else "",
            'censys_key': censys_key.api_key if censys_key else "",
            'leaklookup_key': context['leaklookup_key'].key if context['leaklookup_key'] else "",
            'hackerone_username': hackerone_username or "",
            'hackerone_key': hackerone_key or "",
            'acunetix_url': context['acunetix_key'].server_url if context['acunetix_key'] else "",
            'acunetix_key': context['acunetix_key'].api_key if context['acunetix_key'] else "",
            'hunterio_key': HunterIOAPIKey.objects.first().key if HunterIOAPIKey.objects.exists() else "",
            'linkedin_username': LinkedInCredentials.objects.first().username if LinkedInCredentials.objects.exists() else "",
            'wpscan_key': WpScanAPIKey.objects.first().key if WpScanAPIKey.objects.exists() else "",
            'projectdiscovery_key': ProjectDiscoveryAPIKey.objects.first().key if ProjectDiscoveryAPIKey.objects.exists() else "",
        })

    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def add_tool(request, slug):
    form = ExternalToolForm()
    if request.method == "POST":
        form = ExternalToolForm(request.POST)
        if form.is_valid():
            # add tool
            install_command = form.cleaned_data['install_command']
            github_clone_path = None
            if 'git clone' in install_command:
                project_name = install_command.split('/')[-1]
                # If project name ends with .git remove it
                if project_name.endswith('.git'):
                    project_name = project_name[:-4]
                github_clone_path = '/usr/src/github/' + project_name
                install_command = install_command + ' ' + github_clone_path + ' && pip3 install -r ' + github_clone_path + '/requirements.txt'

            import threading as _threading
            _threading.Thread(target=run_command, args=(install_command,), daemon=True).start()
            saved_form = form.save()
            if github_clone_path:
                tool = InstalledExternalTool.objects.get(id=saved_form.pk)
                tool.github_clone_path = github_clone_path
                tool.save()

            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'External Tool Successfully Added!'})

            messages.add_message(
                request,
                messages.INFO,
                'External Tool Successfully Added!')
            return http.HttpResponseRedirect(reverse('tool_arsenal', kwargs={'slug': slug}))
        else:
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    context = {
            'settings_nav_active': 'active',
            'form': form
        }
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def modify_tool_in_arsenal(request, slug, id):
    external_tool = get_object_or_404(InstalledExternalTool, id=id)
    form = ExternalToolForm(instance=external_tool)
    if request.method == "POST":
        form = ExternalToolForm(request.POST, instance=external_tool)
        if form.is_valid():
            form.save()
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'success', 'message': 'Tool modified successfully'})
            messages.add_message(
                request,
                messages.INFO,
                'Tool modified successfully')
            return http.HttpResponseRedirect(reverse('tool_arsenal', kwargs={'slug': slug}))
        else:
            if request.headers.get('Accept') == 'application/json':
                return http.JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    else:
        form.set_value(external_tool)
    context = {
            'scan_engine_nav_active':
            'active', 'form': form}
    return render(request, 'dashboard/v3_index.html', context)


@has_permission_decorator(PERM_MODIFY_SYSTEM_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def update_github_tool(request, slug, id):
    tool = get_object_or_404(InstalledExternalTool, id=id)
    if tool.github_clone_path:
        update_command = f"cd {tool.github_clone_path} && git pull"
        if tool.update_command:
             update_command = tool.update_command
        import threading as _threading
        _threading.Thread(target=run_command, args=(update_command,), daemon=True).start()
        messages.add_message(request, messages.INFO, f'Update started for {tool.name}')
    return http.HttpResponseRedirect(reverse('tool_arsenal', kwargs={'slug': slug}))

@has_permission_decorator(PERM_MODIFY_SCAN_CONFIGURATIONS, redirect_url=FOUR_OH_FOUR_URL)
def get_full_yaml_config(request, slug):
    """Retrieve the default YAML configuration.
    
    If the configuration does not exist in the database under 'default_yaml_config',
    it seeds the database using the default_yaml_config.yaml fixture file.

    Args:
        request (HttpRequest): Django HTTP request object.
        slug (str): Slug for target engine configuration.

    Returns:
        JsonResponse: A JSON response containing status and the YAML configuration content.
    """
    try:
        from scanEngine.models import Configuration
        from django.conf import settings
        
        config_obj = Configuration.objects.filter(short_name='default_yaml_config').first()
        if not config_obj:
            file_path = os.path.join(settings.BASE_DIR, 'fixtures', 'default_yaml_config.yaml')
            with open(file_path, 'r') as f:
                content = f.read()
            config_obj = Configuration.objects.create(
                name='Default YAML Config',
                short_name='default_yaml_config',
                content=content
            )
        else:
            content = config_obj.content
            
        return http.JsonResponse({'status': 'success', 'content': content})
    except Exception as e:
        return http.JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def yaml_config_reference(request: HttpRequest, slug: str) -> http.JsonResponse:
    """Return the full YAML configuration reference (static file, all config keys documented)."""
    ref_path = os.path.join(settings.BASE_DIR, 'scanEngine', 'reference', 'full_yaml_config.yaml')
    try:
        with open(ref_path, 'r') as f:
            content = f.read()
        return http.JsonResponse({'status': 'success', 'content': content})
    except OSError:
        return http.JsonResponse(
            {'status': 'error', 'content': '', 'message': 'Reference config not found'},
            status=404,
        )
