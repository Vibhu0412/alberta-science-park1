from rest_framework import serializers
from api.models import User, PersonalInformation, BusinessInformation, UserRole
from .models import ChallengeStatement


class ChallengeStatementSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChallengeStatement
        fields = ['id', 'user', 'challenge_title', 'challenge_description', 'challenge_location', 'industry',
                  'status', 'created_at']
