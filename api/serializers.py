from rest_framework import serializers
# from .signals import create_business_profile
from . import signals
from .activationtokens import account_activation_token
from .models import User, PersonalInformation, BusinessInformation, UserRole, InvitedUser
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, base36_to_int
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util
from ASP_SIT.settings import DOMAIN_NAME
from challenge_creator.serializers import UserSerializer


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password2')
        extra_kwargs = {
            'password': {'write_only': True}
        }
        # depth = 1

    # Validating Password and Confirm Password while Registration
    def validate(self, attrs):
        # try:
            email = attrs.get('email')
            password = attrs.get('password')
            password2 = attrs.get('password2')

    #         print('SERIALIZER EMAIL================', email)
            print('SERIALIZER PASSWORD================', password)
            print('SERIALIZER PASSWORD2================', password2)
    #
    #         leader = self.context.get('leader')
    #         token = self.context.get('token')
    #         company = self.context.get('company')
    #         print('SERIALIZER LEADER================', leader)
    #         print('SERIALIZER TOKEN================', token)
    #         try:
    #             decoded_company_name = smart_str(urlsafe_base64_decode(company))
    #         except:
    #             decoded_company_name = None
    #
    #         if leader is not None and token is not None and decoded_company_name is not None:
    #             invited_by_user_id = smart_str(urlsafe_base64_decode(leader))
    #             # user = InvitedUser.objects.get(user=invited_by_user_id)
    #
    #             # Checking token against "email" bcz "SendInviteLinkSerializer" is bounding token with
    #             # "email" not "user"
    #             if not account_activation_token.check_token(email, token):
    #                 raise serializers.ValidationError("Token is not Valid or expired")
    #
            if password != password2:
                raise serializers.ValidationError("Passwords does not Match")
            return attrs
    #

    #
        # except DjangoUnicodeDecodeError as identifier:
        #     account_activation_token.check_token(email, token)
        #     raise serializers.ValidationError("Token is not Valid or expired")

    def create(self, validated_data):
        instance = User.objects.create_user(**validated_data)
        print('INSTANCE=================', instance)
        # company = self.context.get('company')
        #
        # try:
        #     decoded_company_name = smart_str(urlsafe_base64_decode(company))
        #     print('Decoded Company Name================', decoded_company_name)
        # except:
        #     decoded_company_name = None
        #
        # if decoded_company_name is not None:
        #     print(decoded_company_name)
        #     get_company_data = BusinessInformation.objects.filter(company_name=decoded_company_name).first()
        #     print("BUSINESSS DATA===================", get_company_data)
        #     if get_company_data is not None:
        #         print("COMPANY==================", get_company_data)
        #         data = {
        #             "userid": instance.id,
        #             "company_name": get_company_data.company_name,
        #             "company_description": get_company_data.company_description,
        #             "company_website": get_company_data.company_website,
        #             "company_phone": get_company_data.company_phone,
        #             "company_address_line_1": get_company_data.company_address_line_1,
        #             "company_address_line_2": get_company_data.company_address_line_2,
        #             "company_classification": get_company_data.company_classification,
        #             "company_city": get_company_data.company_city,
        #             "company_state": get_company_data.company_state,
        #             "company_country": get_company_data.company_country
        #         }
        #         signals.create_business_profile.send(sender=User, **data)
        #
        #         # create_business_profile.send(sender=User, **data)
        #     else:
        #         raise serializers.ValidationError('Company Profile Does Not Exists.')
        #
        # try:
        #     invited_user = InvitedUser.objects.get(email=instance.email)
        #     print('Invited User ', invited_user)
        #     # Setting the registration value to True
        #     invited_user.is_registered = True
        #     invited_user.save()
        #
        #     # Updating the can_invite_others field of user
        #     instance.can_invite_others = invited_user.can_invite_others
        #     instance.save()
        #
        # except:
        #     pass

        instance.save()

        # roles = validated_data.pop('role')  # removing roles from validated_data

        # for add_role in roles:
        #     print(f'Roles value is --> {add_role.id}')
        #     if add_role.id == 2:
        #         instance.role.add(add_role)
        #         instance.is_challenge_creator = True
        #         instance.save()
        #         print("Upgraded profile to Challenge Creator")
        #     if add_role.id == 3:
        #         instance.role.add(add_role)
        #         instance.is_solution_provider = True
        #         instance.save()
        #         print('Upgraded profile to Solution Provider')
        return instance


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=50)

    # role = serializers.ListField(source='Role', child=serializers.PrimaryKeyRelatedField(queryset=Role.objects.all()))

    class Meta:
        model = User
        fields = ('email', 'password',)

    # def validate(self, attrs):
    #     email = attrs.get('email')
        # user_id = self.context.get('leader')
        # token = self.context.get('token')
        # print('User ID================', user_id)
        # try:
        #     decoded_user_id = smart_str(urlsafe_base64_decode(user_id))
        # except:
        #     decoded_user_id=None
        # company = self.context.get('company')
        #
        # if token is not None and company is not None:
        #     try:
        #         decoded_company_name = smart_str(urlsafe_base64_decode(company))
        #     except:
        #         decoded_company_name = None
        #
        #     print('TOKEN SERIALIZER========', token)
        #     print('DECODED COMPANY NAME========', decoded_company_name)
        #     print('TOKEN CHECK========', account_activation_token.check_token(email, token))
        #     print('Email========', email)
        #
        #     if account_activation_token.check_token(email, token) == True:
        #         user = User.objects.get(email=email)
        #         print("DATA=",
        #               BusinessInformation.objects.filter(company_name=decoded_company_name, user=user).exists())
        #         if BusinessInformation.objects.filter(company_name=decoded_company_name,
        #                                               user=user).exists() == True:
        #             print('FROM PRINT USER ---> User is already registered with this company.')
        #             raise serializers.ValidationError('User is already registered with this company.')
        #         else:
        #             if decoded_company_name is not None:
        #                 print(decoded_company_name)
        #                 get_company_data = BusinessInformation.objects.filter(
        #                     company_name=decoded_company_name).first()
        #                 user = User.objects.get(email=email)
        #                 print("USER===================", user)
        #                 if get_company_data is not None:
        #                     print("COMPANY==================", get_company_data)
        #                     data = {
        #                         "userid": user.id,
        #                         "user": user,
        #                         "company_name": get_company_data.company_name,
        #                         "company_description": get_company_data.company_description,
        #                         "company_website": get_company_data.company_website,
        #                         "company_phone": get_company_data.company_phone,
        #                         "company_address_line_1": get_company_data.company_address_line_1,
        #                         "company_address_line_2": get_company_data.company_address_line_2,
        #                         "company_classification": get_company_data.company_classification,
        #                         "company_city": get_company_data.company_city,
        #                         "company_state": get_company_data.company_state,
        #                         "company_country": get_company_data.company_country
        #                     }
        #                     signals.create_business_profile.send(sender=User, **data)
        #                     get_user = User.objects.get(id=decoded_user_id)
        #                     print('GET USER====', get_user.email)
        #                     InvitedUser.objects.create(email = user.email, is_registered=True,invited_by=get_user,
        #                                                company_name=decoded_company_name )
        #                     # create_business_profile.send(sender=User, **data)
        #
        #     else:
        #         print('You are not authenticated to register with this company.')
        #         raise serializers.ValidationError('You are not authenticated to register with this company.')
        #     return attrs
        #
        # return attrs


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ('password', 'password2',)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError("Passwords does not Match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=50)

    class Meta:
        fields = ('email',)

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID : ", uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Password Reset Token : ", token)
            # Can use user.uid field also
            # link = 'http://localhost:3000/api/user/reset/' + user.uid + '/' + token
            domain = self.context.get('domain')
            print("domain:", domain)
            protocol = self.context.get('protocol')[0]
            print("Protocol:", protocol)
            # link = str(protocol) + '://' + str(domain) + '/reset/?uid=' + uid + '/?token=' + token
            link = DOMAIN_NAME + 'resetpassword/?uid=' + uid + '/?token=' + token

            print("Password Reset Link : ", link)

            # Send Email
            # body = "Click Following Link To Reset Your Password " + link
            body = "Hello, \n We've received a request to reset the password for the Alberta Science Park account " \
                   "associated with  " + user.email + ". No changes have been made to your account yet.\n You can reset" \
                                                      "by clicking on this link : " + link

            # print(body)
            data = {
                'subject': "Reset Password for Alberta Science Park",
                'body': body,
                'to_email': user.email,
            }
            print(data["body"])
            # Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError("You are not a registered User.")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ('password', 'password2',)

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError("Passwords does not Match")

            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not Valid or expired")

            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError("Token is not Valid or expired")


class PersonalProfileSerializer(serializers.ModelSerializer):
    # invited_by = serializers.CharField(source='inviteduser.invited_by')

    class Meta:
        model = PersonalInformation
        fields = ['id', 'first_name', 'last_name', 'personal_email', 'office_phone', 'education', 'position',
                  'languages_spoken', 'experience_level','personal_skills',
                  'address_line_1', 'address_line_2', 'city', 'state', 'country']

    def validate(self, attrs):
        user = self.context.get('user')
        # Will be true if user logs in first time.
        print(user.is_fresh_login)
        if user.is_fresh_login:
            user.is_fresh_login = False
            user.save()
        if PersonalInformation.objects.filter(user=user).exists():
            raise serializers.ValidationError("The Personal Profile for this user already exists")
        return attrs

    def create(self, validated_data):
        user = self.context.get('user')
        return PersonalInformation.objects.create(id=user.id, user=user, **validated_data)


class PersonalProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = PersonalInformation
        fields = ['id', 'first_name', 'last_name', 'personal_email', 'office_phone', 'education', 'position',
                  'languages_spoken', 'experience_level','personal_skills',
                  'address_line_1', 'address_line_2', 'city', 'state', 'country']

    def validate(self, attrs):
        user = self.context.get('user')
        if user.is_fresh_login:
            user.is_fresh_login = False
            user.save()
        return attrs

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        instance.personal_email = validated_data.get("personal_email", instance.personal_email)
        instance.personal_skills = validated_data.get("personal_skills", instance.personal_skills)
        instance.office_phone = validated_data.get("office_phone", instance.office_phone)
        instance.education = validated_data.get("education", instance.education)
        instance.position = validated_data.get("position", instance.position)
        instance.languages_spoken = validated_data.get("languages_spoken", instance.languages_spoken)
        instance.experience_level = validated_data.get("experience_level", instance.experience_level)
        instance.address_line_1 = validated_data.get("address_line_1", instance.address_line_1)
        instance.address_line_2 = validated_data.get("address_line_2", instance.address_line_2)
        instance.city = validated_data.get("city", instance.city)
        instance.state = validated_data.get("state", instance.state)
        instance.country = validated_data.get("country", instance.country)

        instance.save()
        return instance


class BusinessProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessInformation
        fields = ['id', 'company_name', 'company_website', 'company_description', 'company_email', 'company_phone',
                  'company_address_line_1',
                  'company_address_line_2', 'company_classification', 'company_city', 'company_state',
                  'company_country', 'company_website', 'company_description']

    def validate(self, attrs):
        user = self.context.get('user')
        company = self.context.get('user')
        try:
            decoded_company_name = smart_str(urlsafe_base64_decode(company))
        except:
            decoded_company_name = None
        # Will be true if user logs in first time.
        print(user.is_fresh_login)
        if user.is_fresh_login:
            user.is_fresh_login = False
            user.save()
        if BusinessInformation.objects.filter(user=user, company_name=decoded_company_name).exists():
            raise serializers.ValidationError("The Business Profile for this user already exists")
        return attrs

    def create(self, validated_data):
        user = self.context.get('user')
        return BusinessInformation.objects.create(userid=user.id, user=user, invite_through_company=True,
                                                  **validated_data)


class BusinessProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessInformation
        fields = ['id', 'company_name', 'company_website', 'company_description', 'company_email', 'company_phone',
                  'company_address_line_1',
                  'company_address_line_2', 'company_classification', 'company_city', 'company_state',
                  'company_country', 'company_website', 'company_description']

    def validate(self, attrs):
        user = self.context.get('user')
        if user.is_fresh_login:
            user.is_fresh_login = False
            user.save()
        return attrs

    def update(self, instance, validated_data):
        instance.company_name = validated_data.get("company_name", instance.company_name)
        instance.company_website = validated_data.get("company_website", instance.company_website)
        instance.company_description = validated_data.get("company_description", instance.company_description)
        instance.company_email = validated_data.get("company_email", instance.company_email)
        instance.company_phone = validated_data.get("company_phone", instance.company_phone)
        instance.company_address_line_1 = validated_data.get("company_address_line_1", instance.company_address_line_1)
        instance.company_address_line_2 = validated_data.get("company_address_line_2", instance.company_address_line_2)
        instance.company_classification = validated_data.get("company_classification", instance.company_classification)
        instance.company_city = validated_data.get("company_city", instance.company_city)
        instance.company_state = validated_data.get("company_state", instance.company_state)
        instance.company_country = validated_data.get("company_country", instance.company_country)
        instance.company_website = validated_data.get("company_website", instance.company_website)
        instance.company_description = validated_data.get("company_description", instance.company_description)

        instance.save()
        return instance


class RoleRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('role',)

    # Validating Role and updating user flags particular to roles.
    def validate(self, attrs):
        my_role = attrs.get('role')
        user = self.context.get('user')

        for rolex in my_role:
            if rolex.id == 1:
                user.role.add(rolex)
                user.is_admin = True
                user.save()
                # print("Upgraded profile to Admin")
            if rolex.id == 2:
                user.role.add(rolex)
                user.is_challenge_creator = True
                user.save()
                # print("Upgraded profile to Challenge Creator")
            if rolex.id == 3:
                user.role.add(rolex)
                user.is_solution_provider = True
                user.save()
                # print('Upgraded profile to Solution Provider')
            if rolex.id == 4:
                user.role.add(rolex)
                user.is_manager = True
                user.save()
                # print('Upgraded profile to Manager')
            if rolex.id == 5:
                user.role.add(rolex)
                user.is_staff = True
                user.save()
                # print('Upgraded profile to God Level Admin')
        return attrs



################### FUNCTION TO CREATE INVITE LINK #####################
def create_invite_link(user_id, company_name, domain, protocol, email, url):
    leader = urlsafe_base64_encode(force_bytes(user_id))
    print("Encoded UID : ", leader)
    company = urlsafe_base64_encode(force_bytes(company_name))
    print("Encoded Company : ", company)

    # Making custom token with the use of email! Cool Stuff.
    token = account_activation_token.make_token(email)
    print("Invitation Token : ", token)

    # link = str(protocol) + '://' + str(domain) + \
    #        f'/{url}?leader=' + leader + '&token=' + token + '&company=' + company

    link = DOMAIN_NAME + url

    print("User Invitation Link : ", link)
    return link



class SendInviteLinkSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=50)
    company_name = serializers.CharField(max_length=50)
    can_invite_others = serializers.BooleanField()

    class Meta:
        fields = ('email', 'can_invite_others', 'company_name')

    def validate(self, attrs):
        email = attrs.get('email')
        can_invite_others = attrs.get('can_invite_others')
        company_name = attrs.get('company_name')
        print("Company Name==========", company_name)
        print("INVITE OTHER===========", can_invite_others)
    #     print(email)
        user = self.context.get('user')
        print("===========", user)
        domain = self.context.get('domain')
        # protocol = self.context.get('protocol')[0]
        protocol = self.context.get('protocol')
        url = self.context.get('url')
        if BusinessInformation.objects.filter(user_id=user, invite_through_company=True).exists() == True:
            if BusinessInformation.objects.filter(user_id=user).exists() == True:
                link = create_invite_link(user.id, company_name, domain, protocol, email, url)

                print("=============")
                # Send Email
                # body = "Click Following Link To Reset Your Password " + link
                body = "Hello, \n We are pleased to inform you that you have been invited to the Alberta Science Park " \
                       "by" + company_name + \
                       " .Please visit this link " + link + " to get started. Thanks"
                # print(body)
                data = {
                    'subject': "Invitation to Collaborate at Alberta Science Park",
                    'body': body,
                    'to_email': email,
                }
                Util.send_email(data)
                # Util.send_email(data,link, company_name)
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                return attrs

            else:
                raise serializers.ValidationError("You are not authorized to "
                                                  "Invite other with this company profile.")
        else:
            raise serializers.ValidationError("You are not authorized to Invite other "
                                              "with this company profile.Please contact administrator.")


    def create(self, validated_data):
        validated_data["invited_by"] = self.context.get('user')
        print("VALIDATED ======= ", validated_data['invited_by'])

        check_company_name_exists = BusinessInformation.objects.filter(company_name=validated_data["company_name"])
        print("COMPANY=====", check_company_name_exists)
        if check_company_name_exists is not None:
            print("VALIDATED DATA ====", validated_data)
            return InvitedUser.objects.create(**validated_data)
        else:
            raise serializers.ValidationError("Please Use Existing Company Name.")

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email',instance.email)
        instance.company_name = validated_data.get('company_name',instance.company_name)
        instance.can_invite_others = validated_data.get('can_invite_others',instance.can_invite_others)
        instance.save()
        return instance


class FetchInvitedUserSerializer(serializers.ModelSerializer):
    invited_by = UserSerializer()
    class Meta:
        model = InvitedUser
        fields = "__all__"


class FetchCompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessInformation
        fields = ('id', 'user', 'company_name')


class InviteNotificationSerializer(serializers.ModelSerializer):
    invited_by = UserSerializer()
    class Meta:
        model = InvitedUser
        fields=('id','invited_by','company_name','is_active','is_accepted','is_decline','created_at',)
