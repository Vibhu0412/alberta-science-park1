from rest_framework import serializers
from api.models import User, PersonalInformation, BusinessInformation, UserRole
from .models import SolutionInformationProfile


class SolutionInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SolutionInformationProfile
        fields = "__all__"


