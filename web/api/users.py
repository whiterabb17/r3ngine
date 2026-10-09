from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rolepermissions.exceptions import RoleDoesNotExist
from rolepermissions.roles import assign_role, clear_roles
from api.serializers import UserSerializer
from api.permissions import IsSysAdmin
from reNgine.definitions import PERM_MODIFY_SYSTEM_CONFIGURATIONS

User = get_user_model()

class UserManageViewSet(viewsets.ModelViewSet):
	"""
	A ViewSet for managing User creation, editing, status toggling, deletion, and profile retrieval.
	Requires SysAdmin permission for all actions except displaying the currently logged-in user's own profile.
	"""
	queryset = User.objects.all().order_by('date_joined')
	serializer_class = UserSerializer

	def get_permissions(self):
		"""
		Retrieve the permissions required for the current request's action.
		
		Returns:
			list: A list of permission instances required for the action.
		"""
		if self.action == 'me':
			return [IsAuthenticated()]
		return [IsSysAdmin()]

	def get_queryset(self):
		"""
		Retrieve the base queryset for listing or retrieving users.
		
		Returns:
			QuerySet: The queryset containing all users ordered by join date.
		"""
		return super().get_queryset()

	def create(self, request, *args, **kwargs):
		"""
		Create a new user with a specified username, password, and system role.

		Args:
			request (Request): DRF request object containing:
				- username (str): The username for the new account (required).
				- password (str): The password for the new account (required).
				- role (str, optional): The django-role-permissions role name to assign.
				  Defaults to 'penetration_tester'. Must be a valid role.

		Returns:
			Response: A serialized representation of the newly created User if successful (HTTP 201),
			or an error message otherwise (HTTP 400).
		"""
		username = request.data.get('username')
		password = request.data.get('password')
		role = request.data.get('role', 'penetration_tester')
		
		# Ensure required fields are provided
		if not username or not password:
			return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
		
		try:
			# One transaction, so a bad role does not leave a user without one.
			with transaction.atomic():
				user = User.objects.create_user(username=username, password=password)
				assign_role(user, role)
		except IntegrityError:
			return Response({'error': 'A user with that username already exists.'}, status=status.HTTP_400_BAD_REQUEST)
		except RoleDoesNotExist:
			return Response({'error': 'Unknown role.'}, status=status.HTTP_400_BAD_REQUEST)
		serializer = self.get_serializer(user)
		return Response(serializer.data, status=status.HTTP_201_CREATED)

	@action(detail=True, methods=['post'])
	def toggle_status(self, request, pk=None):
		"""
		Toggle the active status (enabled/disabled) of a specific user.
		Prevents administrative users from disabling their own accounts.

		Args:
			request (Request): DRF request object.
			pk (int): The primary key ID of the User to toggle.

		Returns:
			Response: Success status and the new boolean active state if successful (HTTP 200),
			or an error message otherwise (HTTP 400).
		"""
		user = self.get_object()
		# Prevent an administrator from accidentally disabling their own active account
		if user == request.user:
			return Response({'error': 'Cannot disable your own account'}, status=status.HTTP_400_BAD_REQUEST)
		
		# Toggle the active state and commit the change to the database
		user.is_active = not user.is_active
		user.save()
		return Response({'status': 'success', 'is_active': user.is_active})

	@action(detail=True, methods=['post'])
	def update_user(self, request, pk=None):
		"""
		Update an existing user's role and/or password.

		Args:
			request (Request): DRF request object containing:
				- role (str, optional): The new role name to assign.
				- password (str, optional): A new password string to hash and update.
			pk (int): The primary key ID of the User to update.

		Returns:
			Response: Success dictionary (HTTP 200) if update completes successfully,
			or an error response if a RoleDoesNotExist is encountered.
		"""
		user = self.get_object()
		role = request.data.get('role')
		password = request.data.get('password')
		
		# If a role string is supplied, clear any prior roles and assign the new role
		if role:
			clear_roles(user)
			assign_role(user, role)
		
		# If a password string is supplied, set and hash the password, then save the model
		if password:
			user.set_password(password)
			user.save()
			
		return Response({'status': 'success'})

	@action(detail=False, methods=['get'])
	def me(self, request):
		"""
		Retrieve the details and serialized profile of the currently logged-in user.

		Args:
			request (Request): DRF request object representing the authenticated caller.

		Returns:
			Response: Serialized representation of request.user (HTTP 200).
		"""
		serializer = self.get_serializer(request.user)
		return Response(serializer.data)
