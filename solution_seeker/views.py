from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet
from .serializers import SolutionInformationSerializer
from .models import SolutionInformationProfile
from .permissions import IsSolutionProvider, IsOwner, IsManager
from .renderers import SolutionSeekerRenderer
from rest_framework import status
from rest_framework.response import Response


# Create your views here
class SolutionInformationViewSet(ModelViewSet):
    serializer_class = SolutionInformationSerializer
    queryset = SolutionInformationProfile.objects.all()
    permission_classes = [IsAuthenticated, IsSolutionProvider | IsManager]
    renderer_classes = [SolutionSeekerRenderer]

    def create(self, request, *args, **kwargs):
        solution_profile_data = self.request.data
        solution_profile_data['user'] = self.request.user.id

        serializer = SolutionInformationSerializer(data=solution_profile_data)

        if serializer.is_valid():
            serializer.save(id=self.request.user.id)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


