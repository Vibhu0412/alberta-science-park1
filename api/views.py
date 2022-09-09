from django.http import Http404
from django.shortcuts import render
from .models import User, PersonalInformation, BusinessInformation, UserRole, InvitedUser
from .serializers import UserRegistrationSerializer, UserLoginSerializer, \
    UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, \
    PersonalProfileSerializer, PersonalProfileUpdateSerializer, BusinessProfileUpdateSerializer, \
    BusinessProfileSerializer, RoleRegisterSerializer, SendInviteLinkSerializer, FetchInvitedUserSerializer, \
    FetchCompanySerializer, InviteNotificationSerializer
from . import signals
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str, force_bytes
from django.utils.http import  urlsafe_base64_decode
from .activationtokens import account_activation_token

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
        # leader = request.query_params.get('leader')
        # invite_token = request.query_params.get('token')
        # company = request.query_params.get('company')
        # print("LEADER=========",leader)
        # print("invite_token=========", invite_token)
        # print("COMAPNY NAME IN VIEWS=========", company)

        print(request.data)

        serializer = self.serializer_class(data=request.data)
        print("SERIALIZER============", serializer)
        valid = serializer.is_valid(raise_exception=False)
        print('VALID ==== ', valid)
        if valid:
            user = serializer.save()
            access_token = get_tokens_for_user(user)
            status_code = status.HTTP_201_CREATED

            response = {
                'token': access_token,
                'success': True,
                'message': "User successfully registered!",
                'user': {
                    'email': serializer.data.get('email'),
                    # 'role': serializer.data.get('role'),
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
        leader = request.query_params.get('leader')
        invite_token = request.query_params.get('token')
        company = request.query_params.get('company')
        accept_reject = request.query_params.get('accept')
        print("LEADER=========", leader)
        print("invite_token=========", invite_token)
        print("COMAPNY NAME IN VIEWS=========", company)

        serializer = self.serializer_class(data=request.data, context={'leader': leader, 'token': invite_token,
                                            'company': company,'accept_reject':accept_reject})

        # serializer = self.serializer_class(data=request.data)
        valid = serializer.is_valid(raise_exception=True)

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
                # my_role = UserRole.objects.filter(role__email=email)
                # roles_list = []
                # for role in my_role:
                #     roles_list.append(role.id)



                response = {
                    'token': token,
                    'success': True,
                    'message': "User logged in successfully",
                    'status': status_code,
                    'user': {
                        'id': user.id,
                        'email': email,
                        'username': user.username,
                        # 'role': roles_list,
                        'is_fresh_login': user.is_fresh_login,
                        # 'is_challenge_creator': user.is_challenge_creator,
                        # 'is_solution_provider': user.is_solution_provider,
                        # 'is_manager': user.is_manager,
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
            # my_role = UserRole.objects.filter(role__email=request.user.email)
            # roles_list = []
            # for role in my_role:
            #     roles_list.append(role.id)

            # invited_by = InvitedUser
            if InvitedUser.objects.filter(email=request.user.email).exists():
                user_invited = InvitedUser.objects.filter(email=request.user.email).values()
                print("*************", user_invited)
                invited_by = user_invited[0]['invited_by_id']
            else:
                invited_by = None

            # Getting Account Information
            user_info = User.objects.get(id=request.user.id)
            # print(user_info.invitedby.select_related('invited_by'))
            user_data = {
                'id': user_info.id,
                'email': user_info.email,
                'invited_by': invited_by,
                # 'role': roles_list,
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
            query = BusinessInformation.objects.filter(user=request.user)
            serializer = self.serializer_class(query, many=True)

            # # Fetching all the roles for the user
            # my_role = UserRole.objects.filter(role__email=request.user.email)
            # roles_list = []
            # for role in my_role:
            #     roles_list.append(role.id)

            # Getting Account Information
            user_info = User.objects.get(id=request.user.id)
            user_data = {
                'email': user_info.email,
                # 'role': roles_list,
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

    def get_obj(self, pk):
        try:
            return BusinessInformation.objects.get(id=pk)
        except BusinessInformation.DoesNotExist:
            response = {
                'success': False,
                'message':'Busniess Information Does Not Exists.',
                'status': status.HTTP_400_BAD_REQUEST
            }
            return Response({'response':response},status=status.HTTP_400_BAD_REQUEST)

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


    def delete(self, request, pk):
        delete_obj = self.get_obj(pk)
        delete_obj.delete()
        return Response({'msg':'Data Deleted','status':status.HTTP_204_NO_CONTENT},
                        status=status.HTTP_204_NO_CONTENT)


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


class SendInviteLinkView(APIView):
    serializer_class = SendInviteLinkSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]


    def post(self, request):
        email = request.data['email']
        company_name = request.data['company_name']
        if User.objects.filter(email=email).exists()==True:

            get_user_id = User.objects.get(email=email)
            if BusinessInformation.objects.filter(user=get_user_id.id,
                                                  company_name=company_name).exists()==False:
                current_site = get_current_site(request)
                protocol = 'https' if request.is_secure() else 'http',  # Your personal tweak
                print("REQUEST ====== ", request.data)
                serializer = SendInviteLinkSerializer(data=request.data, context={'protocol': protocol,
                                                                               'domain': current_site,
                                                                        'url':'login/','user': request.user})

                valid = serializer.is_valid(raise_exception=True)
                print('VALID****************', valid)
                if valid:
                    serializer.save()
                    status_code = status.HTTP_200_OK
                    response = {
                        'success': True,
                        'statusCode': status_code,
                        'message': "Invitation Sent.",
                    }
                    return Response(response, status=status_code)
                response = {
                    'success': False,
                    'message': serializer.errors["non_field_errors"],
                    'status': status.HTTP_400_BAD_REQUEST,
                    # 'errors': serializer.errors,

                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'msg':'This User is already registered With Your Company.'},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            current_site = get_current_site(request)
            protocol = 'https' if request.is_secure() else 'http',  # Your personal tweak
            serializer = self.serializer_class(data=request.data, context={'protocol': protocol, 'domain': current_site,
                                                                     'url':'signup/','user': request.user})
            valid = serializer.is_valid(raise_exception=True)

            if valid:
                serializer.save()
                status_code = status.HTTP_200_OK
                response = {
                    'success': True,
                    'statusCode': status_code,
                    'message': "Invitation Sent.",
                }
                return Response(response, status=status_code)
            response = {
                'success': False,
                'message': serializer.errors["non_field_errors"],
                'status': status.HTTP_400_BAD_REQUEST,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        try:
            invited_user = InvitedUser.objects.get(pk=pk)
        except InvitedUser.DoesNotExist:
            return Response({'message': 'This Id Of Invited User does not exist.'},
            status=status.HTTP_404_NOT_FOUND)

        invited_user_data =invited_user
        print("*&*&*&*&",request.data)
        # serializer = SendInviteLinkSerializer(invited_user_data, data = request.data, partial=True)

        email = request.data['email']
        company_name = request.data['company_name']
        if User.objects.filter(email=email).exists() == True:
            get_user_id = User.objects.get(email=email)
            if BusinessInformation.objects.filter(user=get_user_id.id,
                                                  company_name=company_name).exists() == False:
                current_site = get_current_site(request)
                protocol = 'https' if request.is_secure() else 'http',  # Your personal tweak
                # serializer = self.serializer_class(data=request.data,partial=True,
                #                                    context={'protocol': protocol, 'domain': current_site,
                #                                             'url': 'login/', 'user': request.user})

                serializer = SendInviteLinkSerializer(invited_user_data, data = request.data, partial=True,
                                                      context={'protocol': "", 'domain': "",
                                                            'url': 'login/', 'user': request.user})
                print("jkfduygegijfntijrhriuthnjkgnjbygcfgvhjbjhbijn", serializer)
                valid = serializer.is_valid(raise_exception=True)
                print('VALID****************', valid)
                if valid:
                    status_code = status.HTTP_200_OK
                    response = {
                        'success': True,
                        'statusCode': status_code,
                        'message': "Joining Company Link Sent.",
                    }
                    return Response(response, status=status_code)
                response = {
                    'success': False,
                    'message': serializer.errors["non_field_errors"],
                    'status': status.HTTP_400_BAD_REQUEST,
                    # 'errors': serializer.errors,

                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'msg': 'This User is already registered With Your Company.'},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            current_site = get_current_site(request)
            protocol = 'https' if request.is_secure() else 'http',  # Your personal tweak
            # serializer = self.serializer_class(data=request.data, context={'protocol': protocol, 'domain': current_site,
            #                                                                'url': 'signup/', 'user': request.user})
            serializer = SendInviteLinkSerializer(invited_user_data, data=request.data, partial=True,
                                                  context={'protocol': "", 'domain': "",
                                                           'url': 'signup/', 'user': request.user})
            valid = serializer.is_valid(raise_exception=True)

            if valid:
                serializer.save()
                status_code = status.HTTP_200_OK
                response = {
                    'success': True,
                    'statusCode': status_code,
                    'message': "Invitation Link sent.",
                }
                return Response(response, status=status_code)
            response = {
                'success': False,
                'message': serializer.errors["non_field_errors"],
                'status': status.HTTP_400_BAD_REQUEST,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,pk):
        try:
            invited_user = InvitedUser.objects.get(pk=pk)
            invited_user.delete()
            response = {
                'success': True,
                'statusCode': status.HTTP_204_NO_CONTENT,
                'message': "Successfully Deleted Invited User."
                # 'user': user_data,
            }
            return Response(response,status.HTTP_204_NO_CONTENT)

        except InvitedUser.DoesNotExist:
            return Response({'message': 'This Id Of Invited User does not exist.'},
            status=status.HTTP_404_NOT_FOUND)

class FetchInvitedUserView(APIView):
    serializer_class = FetchInvitedUserSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get(self, request):
        company_name = request.GET.get('company_name')
        try:
            query = InvitedUser.objects.filter(invited_by=request.user.id, company_name=company_name)
            serializer = self.serializer_class(query, many=True)

            # Getting Account Information
            # user_info = User.objects.get(id=request.user.id)
            # user_data = {
            #     'email': user_info.email,
            #     'username': user_info.username,
            #     'is_fresh_login': user_info.is_fresh_login,
            #     'is_challenge_creator': user_info.is_challenge_creator,
            #     'is_solution_provider': user_info.is_solution_provider,
            #     'is_manager': user_info.is_manager,
            # }

            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Successfully fetched Invited Users",
                'payload': serializer.data,
                # 'user': user_data,
            }
            return Response(response, status=status_code)
        except InvitedUser.DoesNotExist:
            response = {
                'success': False,
                'message': "This User has not invited anyone",
                'status': status.HTTP_404_NOT_FOUND,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)

class FetchCompanyApiView(APIView):
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get(self, request):
        try:
            query = BusinessInformation.objects.filter(user=request.user)
            print('QUERY===========', query)
            serializer = FetchCompanySerializer(query, many=True)
            print('SERIALIZER===========', serializer.data)
            # # Fetching all the roles for the user
            # my_role = UserRole.objects.filter(role__email=request.user.email)
            # roles_list = []
            # for role in my_role:
            #     roles_list.append(role.id)

            # Getting Account Information

            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'statusCode': status_code,
                'message': "Successfully fetched Company.",
                'payload': serializer.data
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


class InviteNotificationApiView(APIView):
    serializer_class = InviteNotificationSerializer
    permission_classes = (AllowAny,)
    renderer_classes = [UserRenderer]

    def get(self, request):
        try:
            query = InvitedUser.objects.filter(email = request.user.email).order_by("-id")
            serializer = self.serializer_class(query, many=True)
            response = {
                'success': True,
                'statusCode': status.HTTP_200_OK,
                'message': "Successfully fetched Your Invitations.",
                'payload': serializer.data,
                # 'user': user_data,
            }
            return Response(response, status= status.HTTP_200_OK)
        except InvitedUser.DoesNotExist:
            response = {
                'success': False,
                'message': "You dont have any Invitations.",
                'status': status.HTTP_204_NO_CONTENT,
                # 'errors': serializer.errors,

            }
            return Response(response, status=status.HTTP_204_NO_CONTENT)

    def post(self, request, pk):
        response_of_invitation =  request.data['response_of_invitation']
        invited_user = InvitedUser.objects.get(id=pk)
        print("**************", response_of_invitation)
        print("**************", invited_user.company_name)
        if response_of_invitation == 'Accept':
            get_company_data=BusinessInformation.objects.filter(company_name=invited_user.company_name).first()
            invite = InvitedUser.objects.filter(id = pk).values().last()
            print("INVITE DETAILS  ===== ",invite)

            if BusinessInformation.objects.filter(user = request.user ,
                                                  company_name=invited_user.company_name).exists()==False:

                if get_company_data is not None:
                    print("COMPANY==================", request.user.id)
                    print("COMPANY==================",request.user)
                    data = {
                        "userid": request.user.id,
                        "user": request.user,
                        "company_name": get_company_data.company_name,
                        "company_description": get_company_data.company_description,
                        "company_website": get_company_data.company_website,
                        "company_phone": get_company_data.company_phone,
                        "company_address_line_1": get_company_data.company_address_line_1,
                        "company_address_line_2": get_company_data.company_address_line_2,
                        "company_classification": get_company_data.company_classification,
                        "company_city": get_company_data.company_city,
                        "company_state": get_company_data.company_state,
                        "company_country": get_company_data.company_country,
                        "invite_through_company": invited_user.can_invite_others
                    }
                    print("DATA ************", data)
                    signals.create_business_profile.send(sender=User, **data)
                    InvitedUser.objects.filter(id =pk).update(is_accepted = True)
                    response = {
                        'success': True,
                        'statusCode': status.HTTP_200_OK,
                        'message': "Invitation Accepted.",
                        'is_accepted':True
                    }
                    return Response(response, status=status.HTTP_200_OK)

            else:
                    response = {
                        'success': False,
                        'statusCode': status.HTTP_400_BAD_REQUEST,
                        'message': "Already Registered with this company.",
                    }
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)


        elif response_of_invitation == 'Decline':
            InvitedUser.objects.filter(id=pk).update(is_decline=True)
            response = {
                'success': True,
                'statusCode': status.HTTP_200_OK,
                'message': "Invitation Rejected.",
            }
            return Response(response, status=status.HTTP_200_OK)

        else:
            response = {
                'success': False,
                'statusCode': status.HTTP_200_OK,
                'message': "Invalid Operation.",
                'is_accepted': False
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)



