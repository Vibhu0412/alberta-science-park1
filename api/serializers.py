from rest_framework import serializers
from .models import User, PersonalInformation, BusinessInformation, UserRole
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ('email', 'role', 'password', 'password2')
        extra_kwargs = {
            'password': {'write_only': True}
        }
        # depth = 1

    # Validating Password and Confirm Password while Registration
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError("Passwords does not Match")
        return attrs

    def create(self, validated_data):
        print(validated_data)
        roles = validated_data.pop('role')  # removing roles from validated_data
        print(f'Roles poped out value is --> {roles}')
        instance = User.objects.create_user(**validated_data)
        print(f'Instance value is --> {instance}')
        for add_role in roles:
            print(f'Roles value is --> {add_role.id}')
            if add_role.id == 2:
                instance.role.add(add_role)
                instance.is_challenge_creator = True
                instance.save()
                print("Upgraded profile to Challenge Creator")
            if add_role.id == 3:
                instance.role.add(add_role)
                instance.is_solution_provider = True
                instance.save()
                print('Upgraded profile to Solution Provider')
        return instance


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=50)
    # role = serializers.ListField(source='Role', child=serializers.PrimaryKeyRelatedField(queryset=Role.objects.all()))

    class Meta:
        model = User
        fields = ('email', 'password',)


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
            link = str(protocol) + '://' + str(domain) + '/reset/?uid=' + uid + '/?token=' + token

            print("Password Reset Link : ", link)

            # Send Email
            # body = "Click Following Link To Reset Your Password " + link
            body = "Hello, \n We've received a request to reset the password for the Alberta Science Park account " \
                   "associated with  " + user.email + ". No changes have been made to your account yet.\n You can reset"
                # print(body)
            data = {
                'subject': "Reset Password for Alberta Science Park",
                'body': body,
                'to_email': user.email,
            }
            print(data["body"])
            Util.send_email(data)
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
    class Meta:
        model = PersonalInformation
        fields = ['id', 'first_name', 'last_name', 'personal_email', 'office_phone', 'education', 'position',
                  'languages_spoken', 'experience_level',
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
                  'languages_spoken', 'experience_level',
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
        instance.office_phone = validated_data.get("office_phone", instance.office_phone)
        instance.education = validated_data.get("education", instance.education)
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
        fields = ['id', 'company_name', 'company_email', 'company_phone', 'company_address_line_1',
                  'company_address_line_2', 'company_classification', 'company_city', 'company_state',
                  'company_country', 'company_website', 'company_description']

    def validate(self, attrs):
        user = self.context.get('user')
        # Will be true if user logs in first time.
        print(user.is_fresh_login)
        if user.is_fresh_login:
            user.is_fresh_login = False
            user.save()
        if BusinessInformation.objects.filter(user=user).exists():
            raise serializers.ValidationError("The Business Profile for this user already exists")
        return attrs

    def create(self, validated_data):
        user = self.context.get('user')
        return BusinessInformation.objects.create(id=user.id, user=user, **validated_data)


class BusinessProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessInformation
        fields = ['id', 'company_name', 'company_email', 'company_phone', 'company_address_line_1',
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

