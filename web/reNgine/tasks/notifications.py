import logging
import os
import requests

from reNgine.common_func import *
from reNgine.definitions import *
from startScan.models import ScanHistory, ScanActivity, Vulnerability
from scanEngine.models import EngineType, Notification, Hackerone
from dashboard.models import HackerOneAPIKey

logger = logging.getLogger(__name__)


def send_notif(
		message,
		scan_history_id=None,
		subscan_id=None,
		**options):
	if not 'title' in options:
		message = enrich_notification(message, scan_history_id, subscan_id)
	send_discord_message(message, **options)
	send_slack_message(message)
	send_lark_message(message)
	send_telegram_message(message)


def send_scan_notif(
		scan_history_id,
		subscan_id=None,
		engine_id=None,
		status='RUNNING'):
	"""Send scan status notification. Works for scan or a subscan if subscan_id
	is passed.

	Args:
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
	"""
	from startScan.models import SubScan

	# Get domain, engine, scan_history objects
	scan = ScanHistory.objects.filter(pk=scan_history_id).first()
	if not engine_id and scan:
		engine = scan.scan_type
	else:
		engine = EngineType.objects.filter(pk=engine_id).first()

	subscan = SubScan.objects.filter(pk=subscan_id).first()
	tasks = ScanActivity.objects.filter(scan_of=scan) if scan else 0

	# Build notif options
	url = get_scan_url(scan_history_id, subscan_id)
	title = get_scan_title(scan_history_id, subscan_id)
	fields = get_scan_fields(engine, scan, subscan, status, tasks)

	severity = None
	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)
	opts = {
		'title': title,
		'url': url,
		'fields': fields,
		'severity': severity
	}
	logger.info(f'Sending notification "{title}" (severity: {severity})')

	# inapp notification has to be sent eitherways
	generate_inapp_notification(scan, subscan, status, engine, fields)

	notif = Notification.objects.first()

	if notif and notif.send_scan_status_notif:
		# Send notification
		send_notif(
			msg,
			scan_history_id,
			subscan_id,
			**opts)


def generate_inapp_notification(scan, subscan, status, engine, fields):
	if status == 'COMPLETED':
		status = 'SUCCESS'

	scan_type = "Subscan" if subscan else "Scan"
	domain = subscan.subdomain.name if subscan else scan.domain.name
	duration_msg = None
	redirect_link = None
	title = f"Scan Status Update"
	description = f"Scan status update for {domain}"
	icon = "mdi-information-outline"
	notif_status = 'info'

	if status == 'RUNNING':
		title = f"{scan_type} Started"
		description = f"{scan_type} has been initiated for {domain}"
		icon = "mdi-play-circle-outline"
		notif_status = 'info'
	elif status == 'SUCCESS':
		title = f"{scan_type} Completed"
		description = f"{scan_type} was successful for {domain}"
		icon = "mdi-check-circle-outline"
		notif_status = 'success'
		duration_msg = f'Completed in {fields.get("Duration")}'
	elif status == 'ABORTED':
		title = f"{scan_type} Aborted"
		description = f"{scan_type} was aborted for {domain}"
		icon = "mdi-alert-circle-outline"
		notif_status = 'warning'
		duration_msg = f'Aborted in {fields.get("Duration")}'
	elif status == 'FAILED':
		title = f"{scan_type} Failed"
		description = f"{scan_type} has failed for {domain}"
		icon = "mdi-close-circle-outline"
		notif_status = 'error'
		duration_msg = f'Failed in {fields.get("Duration")}'
	elif status == 'PARTIALLY COMPLETE':
		title = f"{scan_type} Partially Completed"
		description = f"{scan_type} has completed with some failures for {domain}"
		icon = "mdi-alert-circle-outline"
		notif_status = 'warning'
		duration_msg = f'Partially completed in {fields.get("Duration")}'

	description += f"\n• Engine: {engine.engine_name if engine else 'N/A'}"
	slug = scan.domain.project.slug if scan else subscan.scan_history.domain.project.slug
	if duration_msg:
		description += f"\n• {duration_msg}"

	if status != 'RUNNING':
		redirect_link = f"/scan/{slug}/detail/{scan.id}" if scan else None

	create_inappnotification(
		title=title,
		description=description,
		notification_type='project',
		project_slug=slug,
		icon=icon,
		is_read=False,
		status=notif_status,
		redirect_link=redirect_link,
		open_in_new_tab=False
	)


def send_task_notif(
		task_name,
		status=None,
		result=None,
		output_path=None,
		traceback=None,
		scan_history_id=None,
		engine_id=None,
		subscan_id=None,
		severity=None,
		add_meta_info=True,
		update_fields={}):
	"""Send task status notification.

	Args:
		task_name (str): Task name.
		status (str, optional): Task status.
		result (str, optional): Task result.
		output_path (str, optional): Task output path.
		traceback (str, optional): Task traceback.
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
		severity (str, optional): Severity (will be mapped to notif colors)
		add_meta_info (bool, optional): Wheter to add scan / subscan info to notif.
		update_fields (dict, optional): Fields key / value to update.
	"""
	from startScan.models import SubScan

	# Skip send if notification settings are not configured
	notif = Notification.objects.first()
	if not (notif and notif.send_scan_status_notif):
		return

	# Build fields
	url = None
	fields = {}
	if add_meta_info:
		engine = EngineType.objects.filter(pk=engine_id).first()
		scan = ScanHistory.objects.filter(pk=scan_history_id).first()
		subscan = SubScan.objects.filter(pk=subscan_id).first()
		url = get_scan_url(scan_history_id)
		if status:
			fields['Status'] = f'**{status}**'
		if engine:
			fields['Engine'] = engine.engine_name
		if scan:
			fields['Scan ID'] = f'[#{scan.id}]({url})'
		if subscan:
			url = get_scan_url(scan_history_id, subscan_id)
			fields['Subscan ID'] = f'[#{subscan.id}]({url})'
	title = get_task_title(task_name, scan_history_id, subscan_id)
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)

	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())

	# Add fields to update
	for k, v in update_fields.items():
		fields[k] = v

	# Add traceback to notif
	if traceback and notif.send_scan_tracebacks:
		fields['Traceback'] = f'```\n{traceback}\n```'

	# Add files to notif
	files = []
	attach_file = (
		notif.send_scan_output_file and
		output_path and
		result and
		not traceback
	)
	if attach_file:
		output_title = output_path.split('/')[-1]
		files = [(output_path, output_title)]

	# Send notif
	opts = {
		'title': title,
		'url': url,
		'files': files,
		'severity': severity,
		'fields': fields,
		'fields_append': update_fields.keys()
	}
	send_notif(
		msg,
		scan_history_id=scan_history_id,
		subscan_id=subscan_id,
		**opts)


def send_file_to_discord(file_path, title=None):
	notif = Notification.objects.first()
	do_send = notif and notif.send_to_discord and notif.discord_hook_url
	if not do_send:
		return False

	webhook = DiscordWebhook(
		url=notif.discord_hook_url,
		rate_limit_retry=True,
		username=title or "reNgine Discord Plugin"
	)
	with open(file_path, "rb") as f:
		head, tail = os.path.split(file_path)
		webhook.add_file(file=f.read(), filename=tail)
	webhook.execute()


def send_hackerone_report(vulnerability_id):
	"""Send HackerOne vulnerability report.

	Args:
		vulnerability_id (int): Vulnerability id.

	Returns:
		int: HTTP response status code.
	"""
	vulnerability = Vulnerability.objects.get(id=vulnerability_id)
	severities = {v: k for k, v in NUCLEI_SEVERITY_MAP.items()}

	# can only send vulnerability report if team_handle exists and send_report is True and api_key exists
	hackerone = Hackerone.objects.filter(send_report=True).first()
	api_key = HackerOneAPIKey.objects.filter(username__isnull=False, key__isnull=False).first()

	if not (vulnerability.target_domain.h1_team_handle and hackerone and api_key):
		logger.error('Missing required data: team handle, Hackerone config, or API key.')
		return {"status_code": 400, "message": "Missing required data"}

	severity_value = severities[vulnerability.severity]
	tpl = hackerone.report_template or ""

	tpl_vars = {
		'{vulnerability_name}': vulnerability.name,
		'{vulnerable_url}': vulnerability.http_url,
		'{vulnerability_severity}': severity_value,
		'{vulnerability_description}': vulnerability.description or '',
		'{vulnerability_extracted_results}': vulnerability.extracted_results or '',
		'{vulnerability_reference}': vulnerability.reference or '',
	}

	# Replace syntax of report template with actual content
	for key, value in tpl_vars.items():
		tpl = tpl.replace(key, value)

	data = {
		"data": {
			"type": "report",
			"attributes": {
				"team_handle": vulnerability.target_domain.h1_team_handle,
				"title": f'{vulnerability.name} found in {vulnerability.http_url}',
				"vulnerability_information": tpl,
				"severity_rating": severity_value,
				"impact": "More information about the impact and vulnerability can be found here: \n" + vulnerability.reference if vulnerability.reference else "NA",
			}
		}
	}

	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	}

	r = requests.post(
		'https://api.hackerone.com/v1/hackers/reports',
		auth=(api_key.username, api_key.key),
		json=data,
		headers=headers
	)
	response = r.json()
	status_code = r.status_code
	if status_code == 201:
		vulnerability.hackerone_report_id = response['data']["id"]
		vulnerability.open_status = False
		vulnerability.save()
		return {"status_code": r.status_code, "message": "Report sent successfully"}
	logger.error(f"Error sending report to HackerOne")
	return {"status_code": r.status_code, "message": response}
