import logging

from django.db.models import CharField, Q, Value
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsAuditor, IsPenetrationTester
from api.serializers import (
    EndPointChangesSerializer, EndpointOnlyURLsSerializer, EndpointSerializer,
    InterestingEndPointSerializer, ParameterSerializer,
)
from reNgine.common_func import get_interesting_endpoints
from startScan.models import EndPoint, Parameter, ScanHistory, Subdomain

logger = logging.getLogger(__name__)


class EndPointChangesViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	'''
		This viewset will return the EndPoint changes
	'''
	queryset = EndPoint.objects.none()
	serializer_class = EndPointChangesSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		changes = req.query_params.get('changes')
		domain_id = ScanHistory.objects.filter(id=scan_id).first().domain.id
		scan_history = (
			ScanHistory.objects
			.filter(domain=domain_id)
			.filter(tasks__overlap=['fetch_url'])
			.filter(id__lte=scan_id)
			.filter(scan_status=2)
		)
		if scan_history.count() > 1:
			last_scan = scan_history.order_by('-start_scan_date')[1]
			scanned_host_q1 = (
				EndPoint.objects
				.filter(scan_history__id=scan_id)
				.values('http_url')
			)
			scanned_host_q2 = (
				EndPoint.objects
				.filter(scan_history__id=last_scan.id)
				.values('http_url')
			)
			added_endpoints = scanned_host_q1.difference(scanned_host_q2)
			removed_endpoints = scanned_host_q2.difference(scanned_host_q1)
			if changes == 'added':
				return (
					EndPoint.objects
					.filter(scan_history=scan_id)
					.filter(http_url__in=added_endpoints)
					.annotate(change=Value('added', output_field=CharField()))
				)
			elif changes == 'removed':
				return (
					EndPoint.objects
					.filter(scan_history=last_scan)
					.filter(http_url__in=removed_endpoints)
					.annotate(change=Value('removed', output_field=CharField()))
				)
			else:
				added_endpoints = (
					EndPoint.objects
					.filter(scan_history=scan_id)
					.filter(http_url__in=added_endpoints)
					.annotate(change=Value('added', output_field=CharField()))
				)
				removed_endpoints = (
					EndPoint.objects
					.filter(scan_history=last_scan)
					.filter(http_url__in=removed_endpoints)
					.annotate(change=Value('removed', output_field=CharField()))
				)
				changes = added_endpoints.union(removed_endpoints)
				return changes
		return self.queryset

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class InterestingEndpointViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = EndPoint.objects.none()
	serializer_class = EndpointSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		if 'only_endpoints' in self.request.query_params:
			self.serializer_class = InterestingEndPointSerializer
		if scan_id:
			return get_interesting_endpoints(scan_history=scan_id)
		elif target_id:
			return get_interesting_endpoints(target=target_id)
		else:
			return get_interesting_endpoints()

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class ListEndpoints(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request

		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		subdomain_name = req.query_params.get('subdomain_name')
		pattern = req.query_params.get('pattern')

		if scan_id:
			endpoints = (
				EndPoint.objects
				.filter(scan_history__id=scan_id)
			)
		elif target_id:
			endpoints = (
				EndPoint.objects
				.filter(target_domain__id=target_id)
				.distinct()
			)
		else:
			endpoints = EndPoint.objects.all()

		if subdomain_name:
			endpoints = endpoints.filter(subdomain__name=subdomain_name)

		if pattern:
			endpoints = endpoints.filter(matched_gf_patterns__icontains=pattern)

		if 'only_urls' in req.query_params:
			endpoints_serializer = EndpointOnlyURLsSerializer(endpoints, many=True)

		else:
			endpoints_serializer = EndpointSerializer(endpoints, many=True)

		return Response({'endpoints': endpoints_serializer.data})


class EndpointPagination(PageNumberPagination):
	page_size = 25
	page_size_query_param = 'length'
	max_page_size = 200


class EndPointViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	pagination_class = EndpointPagination
	queryset = EndPoint.objects.none()
	serializer_class = EndpointSerializer

	def get_queryset(self):
		req = self.request

		scan_id = req.query_params.get('scan_history')
		target_id = req.query_params.get('target_id')
		url_query = req.query_params.get('query_param')
		subdomain_id = req.query_params.get('subdomain_id')
		project = req.query_params.get('project')

		endpoints_obj = EndPoint.objects.all()
		if project:
			endpoints_obj = endpoints_obj.filter(scan_history__domain__project__slug=project)

		gf_tag = req.query_params.get(
			'gf_tag') if 'gf_tag' in req.query_params else None

		if scan_id:
			endpoints = (
				endpoints_obj
				.filter(scan_history__id=scan_id)
				.distinct()
			)
		else:
			endpoints = endpoints_obj.distinct()

		if url_query:
			endpoints = (
				endpoints
				.filter(Q(target_domain__name=url_query))
				.distinct()
			)

		if gf_tag:
			endpoints = endpoints.filter(matched_gf_patterns__icontains=gf_tag)

		if target_id:
			endpoints = endpoints.filter(target_domain__id=target_id)

		if subdomain_id:
			endpoints = endpoints.filter(subdomain__id=subdomain_id)

		http_status = req.query_params.get('http_status')
		if http_status:
			try:
				endpoints = endpoints.filter(http_status=int(http_status))
			except ValueError:
				pass

		if 'only_urls' in req.query_params:
			self.serializer_class = EndpointOnlyURLsSerializer

		# Filter status code 404 and 0
		# endpoints = (
		# 	endpoints
		# 	.exclude(http_status=0)
		# 	.exclude(http_status=None)
		# 	.exclude(http_status=404)
		# )

		self.queryset = endpoints

		return self.queryset

	def filter_queryset(self, qs):
		qs = self.queryset.filter()
		search_value = self.request.GET.get(u'search[value]', None)
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		if search_value or _order_col or _order_direction:
			order_col = 'content_length'
			if _order_col == '1':
				order_col = 'http_url'
			elif _order_col == '2':
				order_col = 'http_status'
			elif _order_col == '3':
				order_col = 'page_title'
			elif _order_col == '4':
				order_col = 'matched_gf_patterns'
			elif _order_col == '5':
				order_col = 'content_type'
			elif _order_col == '6':
				order_col = 'content_length'
			elif _order_col == '7':
				order_col = 'techs'
			elif _order_col == '8':
				order_col = 'webserver'
			elif _order_col == '9':
				order_col = 'response_time'
			if _order_direction == 'desc':
				order_col = f'-{order_col}'
			# if the search query is separated by = means, it is a specific lookup
			# divide the search query into two half and lookup
			if '=' in search_value or '&' in search_value or '|' in search_value or '>' in search_value or '<' in search_value or '!' in search_value:
				if '&' in search_value:
					complex_query = search_value.split('&')
					for query in complex_query:
						if query.strip():
							qs = qs & self.special_lookup(query.strip())
				elif '|' in search_value:
					qs = Subdomain.objects.none()
					complex_query = search_value.split('|')
					for query in complex_query:
						if query.strip():
							qs = self.special_lookup(query.strip()) | qs
				else:
					qs = self.special_lookup(search_value)
			else:
				qs = self.general_lookup(search_value)
			return qs.order_by(order_col)
		return qs

	def general_lookup(self, search_value):
		return \
			self.queryset.filter(Q(http_url__icontains=search_value) |
								 Q(page_title__icontains=search_value) |
								 Q(http_status__icontains=search_value) |
								 Q(content_type__icontains=search_value) |
								 Q(webserver__icontains=search_value) |
								 Q(techs__name__icontains=search_value) |
								 Q(content_type__icontains=search_value) |
								 Q(parameters__name__icontains=search_value) |
								 Q(matched_gf_patterns__icontains=search_value))

	def special_lookup(self, search_value):
		qs = self.queryset.filter()
		if '=' in search_value:
			search_param = search_value.split("=")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_url' in lookup_title:
				qs = self.queryset.filter(http_url__icontains=lookup_content)
			elif 'page_title' in lookup_title:
				qs = (
					self.queryset
					.filter(page_title__icontains=lookup_content)
				)
			elif 'content_type' in lookup_title:
				qs = (
					self.queryset
					.filter(content_type__icontains=lookup_content)
				)
			elif 'webserver' in lookup_title:
				qs = self.queryset.filter(webserver__icontains=lookup_content)
			elif 'technology' in lookup_title:
				qs = (
					self.queryset
					.filter(techs__name__icontains=lookup_content)
				)
			elif 'gf_pattern' in lookup_title:
				qs = (
					self.queryset
					.filter(matched_gf_patterns__icontains=lookup_content)
				)
			elif 'http_status' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.filter(http_status=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.filter(content_length=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'parameter' in lookup_title:
				qs = (
					self.queryset
					.filter(parameters__name__icontains=lookup_content)
				)
		elif '>' in search_value:
			search_param = search_value.split(">")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_status' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = (
						self.queryset
						.filter(http_status__gt=int_val)
					)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = self.queryset.filter(content_length__gt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
		elif '<' in search_value:
			search_param = search_value.split("<")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_status' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = self.queryset.filter(http_status__lt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = self.queryset.filter(content_length__lt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
		elif '!' in search_value:
			search_param = search_value.split("!")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_url' in lookup_title:
				qs = (
					self.queryset
					.exclude(http_url__icontains=lookup_content)
				)
			elif 'page_title' in lookup_title:
				qs = (
					self.queryset
					.exclude(page_title__icontains=lookup_content)
				)
			elif 'content_type' in lookup_title:
				qs = (
					self.queryset
					.exclude(content_type__icontains=lookup_content)
				)
			elif 'webserver' in lookup_title:
				qs = (
					self.queryset
					.exclude(webserver__icontains=lookup_content)
				)
			elif 'technology' in lookup_title:
				qs = (
					self.queryset
					.exclude(techs__name__icontains=lookup_content)
				)
			elif 'gf_pattern' in lookup_title:
				qs = (
					self.queryset
					.exclude(matched_gf_patterns__icontains=lookup_content)
				)
			elif 'http_status' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.exclude(http_status=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.exclude(content_length=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
		return qs


class ParameterViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Parameter.objects.none()
	serializer_class = ParameterSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_history')
		target_id = req.query_params.get('target_id')
		endpoint_id = req.query_params.get('endpoint_id')

		if scan_id:
			queryset = Parameter.objects.filter(endpoint__scan_history__id=scan_id)
		elif target_id:
			queryset = Parameter.objects.filter(endpoint__target_domain__id=target_id)
		else:
			queryset = Parameter.objects.all()

		if endpoint_id:
			queryset = queryset.filter(endpoint__id=endpoint_id)

		# CPDE intelligence filters
		if req.query_params.get('param_location'):
			queryset = queryset.filter(param_location=req.query_params['param_location'])
		is_auth = req.query_params.get('is_auth_related', '').lower()
		if is_auth == 'true':
			queryset = queryset.filter(is_auth_related=True)
		elif is_auth == 'false':
			queryset = queryset.filter(is_auth_related=False)
		if req.query_params.get('observed_in_js', '').lower() == 'true':
			queryset = queryset.filter(observed_in_js=True)
		if req.query_params.get('observed_in_openapi', '').lower() == 'true':
			queryset = queryset.filter(observed_in_openapi=True)
		if req.query_params.get('observed_in_graphql', '').lower() == 'true':
			queryset = queryset.filter(observed_in_graphql=True)
		confidence_min = req.query_params.get('confidence_min')
		if confidence_min is not None:
			try:
				queryset = queryset.filter(confidence__gte=int(confidence_min))
			except (ValueError, TypeError):
				pass
		if req.query_params.get('data_type'):
			queryset = queryset.filter(data_type=req.query_params['data_type'])

		return queryset.distinct()
