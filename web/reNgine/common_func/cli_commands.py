"""Command-line builders and validators (nmap), CMSeeK runner, XML/ANSI output helpers.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import json
import os
import re
import shlex
import shutil
import subprocess
import logging

import xmltodict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def remove_ansi_escape_sequences(text):
	# Regular expression to match ANSI escape sequences
	ansi_escape_pattern = r'\x1b\[.*?m'

	# Use re.sub() to replace the ANSI escape sequences with an empty string
	plain_text = re.sub(ansi_escape_pattern, '', text)
	return plain_text


def get_cms_details(url):
	"""Get CMS details using cmseek.py.

	Args:
		url (str): HTTP URL.

	Returns:
		dict: Response.
	"""
	# this function will fetch cms details using cms_detector
	response = {}
	subprocess.run(
		['python3', '/usr/src/github/CMSeeK/cmseek.py',
		 '--random-agent', '--batch', '--follow-redirect', '-u', url],
		check=False
	)

	response['status'] = False
	response['message'] = 'Could not detect CMS!'

	parsed_url = urlparse(url)

	domain_name = parsed_url.hostname
	port = parsed_url.port

	find_dir = domain_name

	if port:
		find_dir += f'_{port}'

	# subdomain may also have port number, and is stored in dir as _port

	cms_dir_path =  f'/usr/src/github/CMSeeK/Result/{find_dir}'
	cms_json_path =  cms_dir_path + '/cms.json'

	if os.path.isfile(cms_json_path):
		cms_file_content = json.loads(open(cms_json_path, 'r').read())
		if not cms_file_content.get('cms_id'):
			return response
		response = {}
		response = cms_file_content
		response['status'] = True
		# remove cms dir path
		try:
			shutil.rmtree(cms_dir_path)
		except Exception as e:
			logger.error("Failed to remove CMS scan directory %s: %s", cms_dir_path, e)

	return response


def _build_cmd(cmd, options, flags, sep=" "):
	for k,v in options.items():
		if not v:
			continue
		if v is True:
			cmd += f" {k}"
		else:
			cmd += f" {k}{sep}{v}"

	for flag in flags:
		if not flag:
			continue
		cmd += f" --{flag}"

	return cmd


def get_nmap_cmd(
		input_file,
		cmd=None,
		host=None,
		ports=None,
		output_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		service_detection=True,
		flags=[]):
	if not cmd:
		cmd = 'nmap'

	if ports:
		if isinstance(ports, list):
			ports = ','.join(list(dict.fromkeys([str(p) for p in ports])))
		elif isinstance(ports, str):
			ports = ','.join(list(dict.fromkeys([p.strip() for p in ports.split(',')])))

	options = {
		"-sV": service_detection,
		"-p": ports,
		"--script": script,
		"--script-args": script_args,
		"--max-rate": max_rate,
		"-oX": output_file
	}
	cmd = _build_cmd(cmd, options, flags)

	is_nmap_valid = is_valid_nmap_command(cmd)
	if not is_nmap_valid:
		logger.error('Invalid nmap command or potentially dangerous: %s', cmd)
		return None

	if not input_file:
		cmd += f" {host}" if host else ""
	else:
		cmd += f" -iL {input_file}"

	return cmd


def xml2json(xml):
	with open(xml) as xml_file:
		xml_content = xml_file.read()
	return xmltodict.parse(xml_content)


def is_valid_nmap_command(cmd):
	"""
		Check if the nmap command is valid or not
		This is to check the nmap command before executing it so as to avoid
		command injection attacks
		Args:
			cmd: str: nmap command
		Returns:
			bool: True if valid, False otherwise
	"""
	try:
		parts = shlex.split(cmd)
	except ValueError as e:
		logger.error('Nmap command shlex split failed: %s', e)
		return False

	if not parts:
		logger.error('Nmap command is empty after split')
		return False

	if not (parts[0] == 'nmap' or parts[0].endswith('/nmap') or parts[0].endswith('\\nmap') or parts[0].endswith('\\nmap.exe')):
		logger.error('Nmap command does not start with nmap: %s', parts[0])
		return False

	# Block dangerous shell characters (potentially used with shell=True)
	dangerous_chars = {';', '&', '|', '>', '<', '`', '$', '(', ')'}
	if any(char in cmd for char in dangerous_chars):
		logger.error('Nmap command contains dangerous characters: %s', cmd)
		return False

	for part in parts[1:]: # ignoring nmap the first part of command
		if part.startswith('-') or part.startswith('--'):
			continue

		# check for valid characters, . - etc are allowed in valid nmap command
		# adding : and = to support script args, port specifications and Windows paths
		# adding [] for IPv6, @ for script-args, +!*# for general nmap flexibility
		# adding space to support quoted arguments from shlex.split
		if all(c.isalnum() or c in '.,/-_:=\\ []@+!*#' for c in part):
			continue
		logger.error('Nmap command part rejected by whitelist: %s', part)
		return False
		
	return True
