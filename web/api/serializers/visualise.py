from django.db.models import F, JSONField, Value
from rest_framework import serializers

from reNgine.common_func import get_interesting_subdomains
from startScan.models import (
    Dork, Email, Employee, EndPoint, IpAddress, MetaFinderDocument, Port, ScanHistory, Subdomain,
    Technology, Vulnerability,
)


class VisualiseVulnerabilitySerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Vulnerability
		fields = [
			'description',
			'http_url'
		]

	def get_description(self, vulnerability):
		return vulnerability.name


class VisualisePortSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')
	title = serializers.SerializerMethodField('get_title')

	class Meta:
		model = Port
		fields = [
			'description',
			'is_uncommon',
			'title',
		]

	def get_description(self, port):
		return str(port.number) + "/" + str(port.service_name)

	def get_title(self, port):
		if port.is_uncommon:
			return "Uncommon Port"


class VisualiseTechnologySerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Technology
		fields = [
			'description'
		]

	def get_description(self, tech):
		return tech.name


class VisualiseIpSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')
	children = serializers.SerializerMethodField('get_children')

	class Meta:
		model = IpAddress
		fields = [
			'description',
			'children'
		]

	def get_description(self, Ip):
		return Ip.address

	def get_children(self, ip):
		port = Port.objects.filter(
			ports__in=IpAddress.objects.filter(
				address=ip))
		serializer = VisualisePortSerializer(port, many=True)
		return serializer.data


class VisualiseEndpointSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = EndPoint
		fields = [
			'description',
			'http_url'
		]

	def get_description(self, endpoint):
		return endpoint.http_url


class VisualiseSubdomainSerializer(serializers.ModelSerializer):

	children = serializers.SerializerMethodField('get_children')
	description = serializers.SerializerMethodField('get_description')
	title = serializers.SerializerMethodField('get_title')

	class Meta:
		model = Subdomain
		fields = [
			'description',
			'children',
			'http_status',
			'title',
		]

	def get_description(self, subdomain):
		return subdomain.name

	def get_title(self, subdomain):
		if get_interesting_subdomains(subdomain.scan_history.id).filter(name=subdomain.name).exists():
			return "Interesting"

	def get_children(self, subdomain_name):
		scan_history = self.context.get('scan_history')
		subdomains = (
			Subdomain.objects
			.filter(scan_history=scan_history)
			.filter(name=subdomain_name)
		)

		ips = IpAddress.objects.filter(ip_addresses__in=subdomains)
		ip_serializer = VisualiseIpSerializer(ips, many=True)

		# endpoint = EndPoint.objects.filter(
		#     scan_history=self.context.get('scan_history')).filter(
		#     subdomain__name=subdomain_name)
		# endpoint_serializer = VisualiseEndpointSerializer(endpoint, many=True)

		technologies = Technology.objects.filter(technologies__in=subdomains)
		tech_serializer = VisualiseTechnologySerializer(technologies, many=True)

		vulnerability = (
			Vulnerability.objects
			.filter(scan_history=scan_history)
			.filter(subdomain=subdomain_name)
		)

		return_data = []
		if ip_serializer.data:
			return_data.append({
				'description': 'IPs',
				'children': ip_serializer.data
			})
		# if endpoint_serializer.data:
		#     return_data.append({
		#         'description': 'Endpoints',
		#         'children': endpoint_serializer.data
		#     })
		if tech_serializer.data:
			return_data.append({
				'description': 'Technologies',
				'children': tech_serializer.data
			})

		if vulnerability:
			vulnerability_data = []
			critical = vulnerability.filter(severity=4)
			if critical:
				critical_serializer = VisualiseVulnerabilitySerializer(
					critical,
					many=True
				)
				vulnerability_data.append({
					'description': 'Critical',
					'children': critical_serializer.data
				})
			high = vulnerability.filter(severity=3)
			if high:
				high_serializer = VisualiseVulnerabilitySerializer(
					high,
					many=True
				)
				vulnerability_data.append({
					'description': 'High',
					'children': high_serializer.data
				})
			medium = vulnerability.filter(severity=2)
			if medium:
				medium_serializer = VisualiseVulnerabilitySerializer(
					medium,
					many=True
				)
				vulnerability_data.append({
					'description': 'Medium',
					'children': medium_serializer.data
				})
			low = vulnerability.filter(severity=1)
			if low:
				low_serializer = VisualiseVulnerabilitySerializer(
					low,
					many=True
				)
				vulnerability_data.append({
					'description': 'Low',
					'children': low_serializer.data
				})
			info = vulnerability.filter(severity=0)
			if info:
				info_serializer = VisualiseVulnerabilitySerializer(
					info,
					many=True
				)
				vulnerability_data.append({
					'description': 'Informational',
					'children': info_serializer.data
				})
			unknown = vulnerability.filter(severity=-1)
			if unknown:
				unknown_serializer = VisualiseVulnerabilitySerializer(
					unknown,
					many=True
				)
				vulnerability_data.append({
					'description': 'Unknown',
					'children': unknown_serializer.data
				})

			if vulnerability_data:
				return_data.append({
					'description': 'Vulnerabilities',
					'children': vulnerability_data
				})

		if subdomain_name.screenshot_path:
			return_data.append({
				'description': 'Screenshot',
				'screenshot_path': subdomain_name.screenshot_path
			})
		return return_data


class VisualiseEmailSerializer(serializers.ModelSerializer):
	title = serializers.SerializerMethodField('get_title')
	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Email
		fields = [
			'description',
			'password',
			'title'
		]

	def get_description(self, email):
		if email.password:
			return email.address + " > " + email.password
		return email.address

	def get_title(self, email):
		if email.password:
			return "Exposed Creds"


class VisualiseDorkSerializer(serializers.ModelSerializer):

	title = serializers.SerializerMethodField('get_title')
	description = serializers.SerializerMethodField('get_description')
	http_url = serializers.SerializerMethodField('get_http_url')

	class Meta:
		model = Dork
		fields = [
			'title',
			'description',
			'http_url'
		]

	def get_title(self, dork):
		return dork.type

	def get_description(self, dork):
		return dork.type

	def get_http_url(self, dork):
		return dork.url


class VisualiseEmployeeSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Employee
		fields = [
			'description'
		]

	def get_description(self, employee):
		if employee.designation:
			return employee.name + '--' + employee.designation
		return employee.name


class VisualiseDataSerializer(serializers.ModelSerializer):

	title = serializers.ReadOnlyField(default='Target')
	description = serializers.SerializerMethodField('get_description')
	children = serializers.SerializerMethodField('get_children')

	class Meta:
		model = ScanHistory
		fields = [
			'description',
			'title',
			'children',
		]

	def get_description(self, scan_history):
		return scan_history.domain.name

	def get_children(self, history):
		scan_history = ScanHistory.objects.filter(id=history.id)

		subdomain = Subdomain.objects.filter(scan_history=history)
		subdomain_serializer = VisualiseSubdomainSerializer(
			subdomain,
			many=True,
			context={'scan_history': history})

		email = Email.objects.filter(emails__in=scan_history)
		email_serializer = VisualiseEmailSerializer(email, many=True)

		dork = Dork.objects.filter(dorks__in=scan_history)
		dork_serializer = VisualiseDorkSerializer(dork, many=True)

		employee = Employee.objects.filter(employees__in=scan_history)
		employee_serializer = VisualiseEmployeeSerializer(employee, many=True)

		metainfo = MetaFinderDocument.objects.filter(
			scan_history__id=history.id)

		return_data = []

		if subdomain_serializer.data:
			return_data.append({
				'description': 'Subdomains',
				'children': subdomain_serializer.data})

		if email_serializer.data or employee_serializer.data or dork_serializer.data or metainfo:
			osint_data = []
			if email_serializer.data:
				osint_data.append({
					'description': 'Emails',
					'children': email_serializer.data})
			if employee_serializer.data:
				osint_data.append({
					'description': 'Employees',
					'children': employee_serializer.data})
			if dork_serializer.data:
				osint_data.append({
					'description': 'Dorks',
					'children': dork_serializer.data})

			if metainfo:
				metainfo_data = []
				usernames = (
					metainfo
					.annotate(description=F('author'))
					.values('description')
					.distinct()
					.annotate(children=Value([], output_field=JSONField()))
					.filter(author__isnull=False)
				)

				if usernames:
					metainfo_data.append({
						'description': 'Usernames',
						'children': usernames})

				software = (
					metainfo
					.annotate(description=F('producer'))
					.values('description')
					.distinct()
					.annotate(children=Value([], output_field=JSONField()))
					.filter(producer__isnull=False)
				)

				if software:
					metainfo_data.append({
						'description': 'Software',
						'children': software})

				os = (
					metainfo
					.annotate(description=F('os'))
					.values('description')
					.distinct()
					.annotate(children=Value([], output_field=JSONField()))
					.filter(os__isnull=False)
				)

				if os:
					metainfo_data.append({
						'description': 'OS',
						'children': os})

				if metainfo_data:
					osint_data.append({
						'description': 'Documents',
						'children': metainfo_data})

			if osint_data:
				return_data.append({
					'description': 'OSINT',
					'children': osint_data})

		return return_data
