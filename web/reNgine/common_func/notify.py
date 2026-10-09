"""Outbound notifications (Telegram, Slack, Lark, Discord, Expo push), in-app notifications and message formatting.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import json
import logging

import humanize
import redis
import requests
from time import sleep
from discord_webhook import DiscordEmbed, DiscordWebhook
from django.utils import timezone

from reNgine.definitions import (
	DISCORD_SEVERITY_COLORS,
	NOTIFICATION_STATUS_TYPES,
	PROJECT_LEVEL_NOTIFICATION,
	SYSTEM_LEVEL_NOTIFICATION,
)
from reNgine.settings import DOMAIN_NAME, REDIS_URL
from reNgine.validators import validate_external_url
from dashboard.models import InAppNotification, Project
from scanEngine.models import Notification

logger = logging.getLogger(__name__)


DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(REDIS_URL)


def send_telegram_message(message):
	"""Send Telegram message.

	Args:
		message (str): Message.
	"""
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_telegram and
		notif.telegram_bot_token and
		notif.telegram_bot_chat_id)
	if not do_send:
		return
	telegram_bot_token = notif.telegram_bot_token
	telegram_bot_chat_id = notif.telegram_bot_chat_id
	send_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_bot_chat_id}&parse_mode=Markdown&text={message}'
	requests.get(send_url, timeout=15)


def send_slack_message(message):
	"""Send Slack message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {'text': message}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_slack and
		notif.slack_hook_url)
	if not do_send:
		return
	hook_url = notif.slack_hook_url
	try:
		validate_external_url(hook_url)
	except ValueError:
		return
	requests.post(url=hook_url, data=json.dumps(message), headers=headers, timeout=15)


def send_lark_message(message):
	"""Send lark message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {"msg_type":"interactive","card":{"elements":[{"tag":"div","text":{"content":message,"tag":"lark_md"}}]}}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_lark and
		notif.lark_hook_url)
	if not do_send:
		return
	hook_url = notif.lark_hook_url
	try:
		validate_external_url(hook_url)
	except ValueError:
		return
	requests.post(url=hook_url, data=json.dumps(message), headers=headers, timeout=15)


def send_discord_message(
		message,
		title='',
		severity=None,
		url=None,
		files=None,
		fields={},
		fields_append=[]):
	"""Send Discord message.

	If title and fields are specified, ignore the 'message' and create a Discord
	embed that can be updated later if specifying the same title (title is the
	cache key).

	Args:
		message (str): Message to send. If an embed is used, this is ignored.
		severity (str, optional): Severity. Colors are picked based on severity.
		files (list, optional): List of files to attach to message.
		title (str, optional): Discord embed title.
		url (str, optional): Discord embed URL.
		fields (dict, optional): Discord embed fields.
		fields_append (list, optional): Discord embed field names to update
			instead of overwrite.
	"""

	# Check if do send
	notif = Notification.objects.first()
	if not (notif and notif.send_to_discord and notif.discord_hook_url):
		return False
	try:
		validate_external_url(notif.discord_hook_url)
	except ValueError:
		return False

	# If fields and title, use an embed
	use_discord_embed = fields and title
	if use_discord_embed:
		message = '' # no need for message in embeds

	# Check for cached response in cache, using title as key (stored as JSON message ID)
	cached_msg_id = DISCORD_WEBHOOKS_CACHE.get(title) if title else None

	# Get existing webhook if found in cache (stored as JSON dict)
	cached_webhook_data = DISCORD_WEBHOOKS_CACHE.get(title + '_webhook') if title else None
	if cached_webhook_data:
		wh_dict = json.loads(cached_webhook_data)
		webhook = DiscordWebhook(
			url=wh_dict.get('url', notif.discord_hook_url),
			rate_limit_retry=False,
			content=wh_dict.get('content', message))
		webhook.remove_embeds()
	else:
		webhook = DiscordWebhook(
			url=notif.discord_hook_url,
			rate_limit_retry=False,
			content=message)

	# Get existing embed if found in cache (stored as JSON dict)
	embed = None
	cached_embed_data = DISCORD_WEBHOOKS_CACHE.get(title + '_embed') if title else None
	if cached_embed_data:
		embed_dict = json.loads(cached_embed_data)
		embed = DiscordEmbed(title=embed_dict.get('title', title))
		if embed_dict.get('color'):
			embed.set_color(embed_dict['color'])
		if embed_dict.get('description'):
			embed.set_description(embed_dict['description'])
		for field in embed_dict.get('fields', []):
			embed.add_embed_field(name=field['name'], value=field['value'], inline=field.get('inline', False))
	elif use_discord_embed:
		embed = DiscordEmbed(title=title)

	# Set embed fields
	if embed:
		if url:
			embed.set_url(url)
		if severity:
			embed.set_color(DISCORD_SEVERITY_COLORS[severity])
		embed.set_description(message)
		embed.set_timestamp()
		existing_fields_dict = {field['name']: field['value'] for field in embed.fields}
		logger.debug(''.join([f'\n\t{k}: {v}' for k, v in fields.items()]))
		for name, value in fields.items():
			if not value: # cannot send empty field values to Discord [error 400]
				continue
			value = str(value)
			new_field = {'name': name, 'value': value, 'inline': False}

			# If field already existed in previous embed, update it.
			if name in existing_fields_dict.keys():
				field = [f for f in embed.fields if f['name'] == name][0]

				# Append to existing field value
				if name in fields_append:
					existing_val = field['value']
					existing_val = str(existing_val)
					if value not in existing_val:
						value = f'{existing_val}\n{value}'

					if len(value) > 1024: # character limit for embed field
						value = value[0:1016] + '\n[...]'

				# Update existing embed
				ix = embed.fields.index(field)
				embed.fields[ix]['value'] = value

			else:
				embed.add_embed_field(**new_field)

		webhook.add_embed(embed)

		# Cache webhook and embed data as JSON (never pickle)
		DISCORD_WEBHOOKS_CACHE.set(title + '_webhook', json.dumps({
			'url': webhook.url,
			'content': webhook.content,
		}))
		DISCORD_WEBHOOKS_CACHE.set(title + '_embed', json.dumps({
			'title': embed.title if hasattr(embed, 'title') else title,
			'color': embed.color if hasattr(embed, 'color') else None,
			'description': embed.description if hasattr(embed, 'description') else None,
			'fields': embed.fields if hasattr(embed, 'fields') else [],
		}))

	# Add files to webhook
	if files:
		for (path, name) in files:
			with open(path, 'r') as f:
				content = f.read()
			webhook.add_file(content, name)

	# Edit webhook if it already existed (using cached message ID), otherwise send new
	if cached_msg_id:
		webhook.id = cached_msg_id
		response = webhook.edit(webhook)
	else:
		response = webhook.execute()
		if use_discord_embed and response.status_code == 200:
			try:
				msg_id = response.json().get('id', '')
				DISCORD_WEBHOOKS_CACHE.set(title, msg_id)
			except (ValueError, AttributeError, redis.RedisError):
				# Without the cached id the next update posts a new message instead of editing.
				logger.warning("Could not cache Discord message id for %s", title, exc_info=True)

	# Get status code
	if response.status_code == 429:
		errors = json.loads(
			response.content.decode('utf-8'))
		wh_sleep = (int(errors['retry_after']) / 1000) + 0.15
		sleep(wh_sleep)
		send_discord_message(
				message,
				title,
				severity,
				url,
				files,
				fields,
				fields_append)
	elif response.status_code != 200:
		logger.error(
			'Error while sending webhook data to Discord. HTTP code: %s. Details: %s',
			response.status_code,
			response.content)


def enrich_notification(message, scan_history_id, subscan_id):
	"""Add scan id / subscan id to notification message.

	Args:
		message (str): Original notification message.
		scan_history_id (int): Scan history id.
		subscan_id (int): Subscan id.

	Returns:
		str: Message.
	"""
	if scan_history_id is not None:
		if subscan_id:
			message = f'`#{scan_history_id}_{subscan_id}`: {message}'
		else:
			message = f'`#{scan_history_id}`: {message}'
	return message


def get_scan_title(scan_id, subscan_id=None, task_name=None):
	return f'Subscan #{subscan_id} summary' if subscan_id else f'Scan #{scan_id} summary'


def get_scan_url(scan_id=None, subscan_id=None):
	if scan_id:
		return f'https://{DOMAIN_NAME}/scan/detail/{scan_id}'
	return None


def get_scan_fields(engine, scan, subscan=None, status='RUNNING', tasks=[]):
	scan_obj = subscan if subscan else scan
	if subscan:
		tasks_h = f'`{subscan.type}`'
		host = subscan.subdomain.name
		scan_obj = subscan
	else:
		tasks_h = '• ' + '\n• '.join(f'`{task.name}`' for task in tasks) if tasks else ''
		host = scan.domain.name
		scan_obj = scan

	# Find scan elapsed time
	duration = None
	if scan_obj and status in ['ABORTED', 'FAILED', 'SUCCESS']:
		td = scan_obj.stop_scan_date - scan_obj.start_scan_date
		duration = humanize.naturaldelta(td)
	elif scan_obj:
		td = timezone.now() - scan_obj.start_scan_date
		duration = humanize.naturaldelta(td)

	# Build fields
	url = get_scan_url(scan.id)
	fields = {
		'Status': f'**{status}**',
		'Engine': engine.engine_name if engine else "Default",
		'Scan ID': f'[#{scan.id}]({url})'
	}

	if subscan:
		url = get_scan_url(scan.id, subscan.id)
		fields['Subscan ID'] = f'[#{subscan.id}]({url})'

	if duration:
		fields['Duration'] = duration

	fields['Host'] = host
	if tasks:
		fields['Tasks'] = tasks_h

	return fields


def get_task_title(task_name, scan_id=None, subscan_id=None):
	if scan_id:
		prefix = f'#{scan_id}'
		if subscan_id:
			prefix += f'-#{subscan_id}'
		return f'`{prefix}` - `{task_name}`'
	return f'`{task_name}` [unbound]'


def get_task_header_message(name, scan_history_id, subscan_id):
	msg = f'`{name}` [#{scan_history_id}'
	if subscan_id:
		msg += f'_#{subscan_id}]'
	msg += 'status'
	return msg


def create_inappnotification(
		title,
		description,
		notification_type=SYSTEM_LEVEL_NOTIFICATION,
		project_slug=None,
		icon="mdi-bell",
		is_read=False,
		status='info',
		redirect_link=None,
		open_in_new_tab=False
):
	"""
		This function will create an inapp notification
		Inapp Notification not to be confused with Notification model 
		that is used for sending alerts on telegram, slack etc.
		Inapp notification is used to show notification on the web app

		Args: 
			title: str: Title of the notification
			description: str: Description of the notification
			notification_type: str: Type of the notification, it can be either
				SYSTEM_LEVEL_NOTIFICATION or PROJECT_LEVEL_NOTIFICATION
			project_slug: str: Slug of the project, if notification is PROJECT_LEVEL_NOTIFICATION
			icon: str: Icon of the notification, only use mdi icons
			is_read: bool: Whether the notification is read or not, default is False
			status: str: Status of the notification (success, info, warning, error), default is info
			redirect_link: str: Link to redirect when notification is clicked
			open_in_new_tab: bool: Whether to open the redirect link in a new tab, default is False

		Returns:
			ValueError: if error
			InAppNotification: InAppNotification object if successful
	"""
	logger.info('Creating InApp Notification with title: %s', title)
	if notification_type not in [SYSTEM_LEVEL_NOTIFICATION, PROJECT_LEVEL_NOTIFICATION]:
		raise ValueError("Invalid notification type")
	
	if status not in [choice[0] for choice in NOTIFICATION_STATUS_TYPES]:
		raise ValueError("Invalid notification status")
	
	project = None
	if notification_type == PROJECT_LEVEL_NOTIFICATION:
		if not project_slug:
			raise ValueError("Project slug is required for project level notification")
		try:
			project = Project.objects.get(slug=project_slug)
		except Project.DoesNotExist as e:
			raise ValueError(f"No project exists: {e}")
		
	notification = InAppNotification(
		title=title,
		description=description,
		notification_type=notification_type,
		project=project,
		icon=icon,
		is_read=is_read,
		status=status,
		redirect_link=redirect_link,
		open_in_new_tab=open_in_new_tab
	)
	notification.save()

	# Dispatch a push notification to all registered mobile devices
	send_mobile_push_notification(
		title=title,
		body=description,
		data={'notification_id': notification.id, 'status': status}
	)

	return notification


def send_mobile_push_notification(title, body, data=None):
	"""
		Send a push notification to all active registered mobile devices
		via the Expo Push Notification Service.

		This function is intentionally fire-and-forget: errors are logged
		but never re-raised so that a push failure never breaks normal
		application flow.

		Args:
			title (str): The notification title shown on the device.
			body (str): The notification body/description text.
			data (dict, optional): Extra JSON payload passed to the app
				when the user taps the notification.
	"""
	try:
		# Import here to avoid circular imports; MobilePushToken lives in dashboard.models
		from dashboard.models import MobilePushToken

		# Collect all active Expo push tokens
		tokens = list(
			MobilePushToken.objects
			.filter(is_active=True)
			.values_list('token', flat=True)
		)

		if not tokens:
			# No registered devices — nothing to do
			return

		# Build one message per token (Expo supports batching up to 100)
		messages = [
			{
				'to': token,
				'title': title,
				'body': body,
				'data': data or {},
				'sound': 'default',
				'priority': 'high',
			}
			for token in tokens
		]

		# Expo Push API endpoint — no auth required for Expo push tokens
		expo_push_url = 'https://exp.host/--/api/v2/push/send'

		response = requests.post(
			expo_push_url,
			json=messages,
			headers={
				'Accept': 'application/json',
				'Accept-Encoding': 'gzip, deflate',
				'Content-Type': 'application/json',
			},
			timeout=10,
		)

		result = response.json()
		# Log any per-token errors returned by Expo
		for ticket in result.get('data', []):
			if ticket.get('status') == 'error':
				logger.warning(
					'[PushNotification] Expo push error: %s — %s',
					ticket.get('message'),
					ticket.get('details'),
				)

	except Exception as e:
		# Never let a push failure crash the calling code
		logger.error('[PushNotification] Failed to dispatch push notifications: %s', e)
