from rest_framework import serializers
from api.models import User, PersonalInformation, BusinessInformation
from .models import ChallengeStatement, Comment


# class PersonalInformationSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields=['id','first_name','last_name']

## New ##



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username',)

class BusinessProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessInformation
        fields = ('id', 'company_name', )

class ListRetrieveChallengeStatementSerializer(serializers.ModelSerializer):
    # full_name = serializers.SerializerMethodField('get_full_name')
    # print('FULL NAME ============', full_name)

    user = UserSerializer()
    company_name =BusinessProfileSerializer()
    # print('user===', user)
    # get_first_name = PersonalInformation.objects.select_related('user__solutioninformationprofile').values()
    # print('First Name ===', get_first_name)

    class Meta:
        model = ChallengeStatement
        fields = ['id', 'user', 'challenge_title', 'challenge_description', 'challenge_location', 'industry','skills',
                  'company_name', 'post_type', 'is_archieve','status_type', 'created_at']

    def get_full_name(self, obj):
        return obj.user.full_name


class ChallengeStatementSerializer(serializers.ModelSerializer):
    # user = UserSerializer()
    class Meta:
        model = ChallengeStatement
        fields = ['id', 'user', 'challenge_title', 'challenge_description', 'challenge_location', 'industry','skills',
                  'company_name', 'post_type','is_archieve','status_type', 'created_at']

class BusinessProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = BusinessInformation
        fields = ['id', 'company_name']

class PostCommentSerializer(serializers.Serializer):
    user_comment = serializers.CharField(max_length=2000)

    class Meta:
        model = Comment
        fields=['id','commented_by', 'company_name','user_comment','post']

    def create(self, validated_data):
        user = User.objects.get(id=self.context.get('user'))
        post = ChallengeStatement.objects.get(id=self.context.get('post_id'))
        try:
            company_name = self.context.get('company_name')
        except:
            company_name = ""

        if not company_name :
            return Comment.objects.create(commented_by=user,
                                          post=post, **validated_data)

        else:
            company_name_object = BusinessInformation.objects.get(id=self.context.get('company_name'))
            print("COMPANY NAME OBJECT =====", company_name_object)
            return Comment.objects.create(commented_by=user, company_name=company_name_object,
                                          post=post, **validated_data)

class ListCommentSerializer(serializers.ModelSerializer):
    # post=ChallengeStatementSerializer()
    commented_by = UserSerializer()
    company_name = BusinessProfileSerializer()
    class Meta:
        model = Comment
        fields= ['id','post','commented_by', 'company_name','user_comment','created_at','updated_at']


