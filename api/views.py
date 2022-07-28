from django.http import Http404
from django.shortcuts import render
from .models import User, PersonalInformation, BusinessInformation, UserRole
from .serializers import UserRegistrationSerializer, UserLoginSerializer, \
    UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, \
    PersonalProfileSerializer, PersonalProfileUpdateSerializer, BusinessProfileUpdateSerializer, \
    BusinessProfileSerializer, RoleRegisterSerializer
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site


# Create your views here.
# Password = "Abc@123456"

# Generate Token Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)
    renderer_classes = [UserRenderer]

    def post(self, request):
        print(request.data)
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=False)
        if valid:
            user = serializer.save()
            token = get_tokens_for_user(user)
            status_code = status.HTTP_201_CREATED

            response = {
                'token': token,
                'success': True,
                'message': "User successfully registered!",
                'user': {
                    'email': serializer.data.get('email'),
                    'role': serializer.data.get('role'),
                }
            }
            return Response(response, status=status_code)
        response = {
            'success': False,
            'message': "User already registered!",
            # 'message': serializer.errors,
            'status': status.HTTP_409_CONFLICT,
            'errors': serializer.errors
        }
        return Response(response, status=status.HTTP_409_CONFLICT)


class UserLoginView(APIView):
    serializer_class = UserLoginSerializer
    permission_classes = (AllowAny,)
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=False)

        if valid:
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)

            if user is not None:
                token = get_tokens_for_user(user)
                status_code = status.HTTP_200_OK
                user = User.objects.get(email=email)
                # my_user = User.objects.filter(role__id__lte=3)

                # Fetching all the roles for the user
                my_role = UserRole.objects.filter(role__email=email)
                roles_list = []
                for role in my_role:
                    roles_list.append(role.id)

                response = {
                    'token': token,
                    'success': True,
                    'message': "User logged in successfully",
                    'status': status_code,
                    'user': {
                        'id': user.id,
                        'email': email,
                        'username': user.username,
                        'role': roles_list,
                        'is_fresh_login': user.is_fresh_login,
                        'is_challenge_creator': user.is_challenge_creator,
                        'is_solution_provider': user.is_solution_provider,
                        'is_manager': user.is_manager,
                    }
                }
                return Response(response, status=status_code)
            else:
                response = {
                    'success': False,
                    'message': "Email or Password is Incorrect",
                    'status': status.HTTP_401_UNAUTHORIZED,
                    'errors': {'non_field_errors': ['Email or Password is Incorrect']},

                }
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        response = {
            'success': False,
            'message': "Please Enter required fields",
            'status': status.HTTP_400_BAD_REQUEST,
            'errors': serializer.errors,

        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UserChangePasswordView(APIView):
    serializer_class = UserChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        valid = serializer.is_valid(raise_exception=False)

        if valid:
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Password Changed Successfully",
            }
            return Response(response, status=status_code)
        response = {
            'success': False,
            'message': serializer.errors["non_field_errors"],
            'status': status.HTTP_400_BAD_REQUEST,
            # 'errors': serializer.errors,

        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    serializer_class = SendPasswordResetEmailSerializer
    renderer_classes = [UserRenderer]

    def post(self, request):
        current_site = get_current_site(request)
        protocol = 'https' if request.is_secure() else 'http',  # Your personal tweak
        serializer = self.serializer_class(data=request.data, context={'protocol': protocol, 'domain': current_site})
        valid = serializer.is_valid(raise_exception=False)

        if valid:
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Password Reset Link sent. Please check your Email",
            }
            return Response(response, status=status_code)
        response = {
            'success': False,
            'message': serializer.errors["non_field_errors"],
            'status': status.HTTP_400_BAD_REQUEST,
            # 'errors': serializer.errors,

        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetView(APIView):
    serializer_class = UserPasswordResetSerializer
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token):
        serializer = self.serializer_class(data=request.data, context={'uid': uid, 'token': token})
        valid = serializer.is_valid(raise_exception=False)

        if valid:
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Password Reset Successfully",
            }
            return Response(response, status=status_code)
        response = {
            'success': False,
            'message': serializer.errors["non_field_errors"],
            'status': status.HTTP_400_BAD_REQUEST,
            # 'errors': serializer.errors,

        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class PersonalProfileCreateView(APIView):
    serializer_class = PersonalProfileSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get(self, request):
        try:
            query = PersonalInformation.objects.get(user=request.user)
            serializer = self.serializer_class(query)

            # Fetching all the roles for the user
            my_role = UserRole.objects.filter(role__email=request.user.email)
            roles_list = []
            for role in my_role:
                roles_list.append(role.id)

            # Getting Account Information
            user_info = User.objects.get(id=request.user.id)
            user_data = {
                'id': user_info.id,
                'email': user_info.email,
                'role': roles_list,
                'username': user_info.username,
                'is_fresh_login': user_info.is_fresh_login,
                'is_challenge_creator': user_info.is_challenge_creator,
                'is_solution_provider': user_info.is_solution_provider,
                'is_manager': user_info.is_manager,
            }

            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Successfully fetched user profile",
                'payload': serializer.data,
                'user': user_data,
            }
            return Response(response, status=status_code)
        except PersonalInformation.DoesNotExist:
            response = {
                'success': False,
                'message': "Profile Does Not Exist for this user",
                'status': status.HTTP_404_NOT_FOUND,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'user': request.user})
        valid = serializer.is_valid(raise_exception=False)

        if valid:
            serializer.save()
            status_code = status.HTTP_201_CREATED
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Profile Created Successfully",
                'payload': serializer.data,
            }
            return Response(response, status=status_code)
        response = {
            'success': False,
            'message': serializer.errors,
            'status': status.HTTP_400_BAD_REQUEST,
            # 'errors': serializer.errors,

        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class PersonalProfileUpdateView(APIView):
    serializer_class = PersonalProfileUpdateSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def put(self, request, pk):
        try:
            query = PersonalInformation.objects.get(id=pk)
            if PersonalInformation.objects.filter(id=pk, user=request.user).exists():
                # query = PersonalInformation.objects.get(id=pk)
                serializer = self.serializer_class(query, data=request.data, context={'user': request.user})
                valid = serializer.is_valid(raise_exception=False)

                if valid:
                    serializer.save()
                    status_code = status.HTTP_200_OK
                    response = {
                        'success': True,
                        'statusCode': status_code,
                        'message': "Profile Updated Successfully",
                        'payload': serializer.data,
                    }
                    return Response(response, status=status_code)
                response = {
                    'success': False,
                    'message': serializer.errors,
                    'status': status.HTTP_400_BAD_REQUEST,
                    # 'errors': serializer.errors,

                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'success': False,
                'statusCode': status.HTTP_401_UNAUTHORIZED,
                'message': "You are not authorized to update this profile.",
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        except PersonalInformation.DoesNotExist:
            response = {
                'success': False,
                'statusCode': status.HTTP_404_NOT_FOUND,
                'message': "Profile Does Not Exist",
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)


class BusinessProfileCreateView(APIView):
    serializer_class = BusinessProfileSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get(self, request):
        try:
            query = BusinessInformation.objects.get(user=request.user)
            serializer = self.serializer_class(query)

            # Fetching all the roles for the user
            my_role = UserRole.objects.filter(role__email=request.user.email)
            roles_list = []
            for role in my_role:
                roles_list.append(role.id)

            # Getting Account Information
            user_info = User.objects.get(id=request.user.id)
            user_data = {
                'email': user_info.email,
                'role': roles_list,
                'username': user_info.username,
                'is_fresh_login': user_info.is_fresh_login,
                'is_challenge_creator': user_info.is_challenge_creator,
                'is_solution_provider': user_info.is_solution_provider,
                'is_manager': user_info.is_manager,
            }

            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Successfully fetched business profile",
                'payload': serializer.data,
                'user': user_data,
            }
            return Response(response, status=status_code)
        except BusinessInformation.DoesNotExist:
            response = {
                'success': False,
                'message': "Profile Does Not Exist for this user",
                'status': status.HTTP_404_NOT_FOUND,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'user': request.user})
        valid = serializer.is_valid(raise_exception=False)

        if valid:
            serializer.save()
            status_code = status.HTTP_201_CREATED
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Business Profile Created Successfully",
                'payload': serializer.data,
            }
            return Response(response, status=status_code)
        response = {
            'success': False,
            'message': serializer.errors,
            'status': status.HTTP_400_BAD_REQUEST,
            # 'errors': serializer.errors,

        }
        return Response(response, status=status.HTTP_400_BAD_REQUEST)


class BusinessProfileUpdateView(APIView):
    serializer_class = BusinessProfileUpdateSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def put(self, request, pk):
        try:
            query = BusinessInformation.objects.get(id=pk)
            if BusinessInformation.objects.filter(id=pk, user=request.user).exists():
                # query = PersonalInformation.objects.get(id=pk)
                serializer = self.serializer_class(query, data=request.data, context={'user': request.user})
                valid = serializer.is_valid(raise_exception=False)

                if valid:
                    serializer.save()
                    status_code = status.HTTP_200_OK
                    response = {
                        'success': True,
                        'statusCode': status_code,
                        'message': "Business Profile Updated Successfully",
                        'payload': serializer.data,
                    }
                    return Response(response, status=status_code)
                response = {
                    'success': False,
                    'message': serializer.errors,
                    'status': status.HTTP_400_BAD_REQUEST,
                    # 'errors': serializer.errors,

                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'success': False,
                'statusCode': status.HTTP_401_UNAUTHORIZED,
                'message': "You are not authorized to update this profile.",
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        except BusinessInformation.DoesNotExist:
            response = {
                'success': False,
                'statusCode': status.HTTP_404_NOT_FOUND,
                'message': "Business Profile Does Not Exist",
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)


class RoleRegisterView(APIView):
    serializer_class = RoleRegisterSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request, pk):
        try:
            user = User.objects.get(id=pk)
            if User.objects.filter(id=pk, email=request.user.email).exists():
                # query = PersonalInformation.objects.get(id=pk)
                serializer = self.serializer_class(data=request.data, context={'user': request.user})
                valid = serializer.is_valid(raise_exception=False)

                if valid:
                    # serializer.save()

                    # Fetching all the roles for the user
                    my_role = UserRole.objects.filter(role__email=user.email)
                    roles_list = []
                    for role in my_role:
                        roles_list.append(role.id)

                    user = User.objects.get(id=pk)

                    status_code = status.HTTP_200_OK
                    response = {
                        'success': True,
                        'statusCode': status_code,
                        'message': "Roles Updated Successfully",
                        # 'payload': serializer.data,
                        'payload': {
                            'id': user.id,
                            'email': user.email,
                            'username': user.username,
                            'role': roles_list,
                            'is_fresh_login': user.is_fresh_login,
                            'is_challenge_creator': user.is_challenge_creator,
                            'is_solution_provider': user.is_solution_provider,
                            'is_manager': user.is_manager,
                        },
                    }
                    return Response(response, status=status_code)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            response = {
                'success': False,
                'statusCode': status.HTTP_401_UNAUTHORIZED,
                'message': "You are not authorized to update this profile.",
            }
            return Response(response, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            response = {
                'success': False,
                'statusCode': status.HTTP_404_NOT_FOUND,
                'message': "User Does Not Exist",
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)
