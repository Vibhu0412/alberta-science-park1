from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet
from challenge_creator.serializers import ChallengeStatementSerializer
from .models import ChallengeStatement
from .permissions import IsChallengeCreator, IsOwner, IsManager
from .renderers import ChallengeCreatorRenderer


# Create your views here
class ChallengeStatementViewSet(ModelViewSet):
    serializer_class = ChallengeStatementSerializer
    queryset = ChallengeStatement.objects.all()
    # permission_classes = [IsAuthenticated, IsChallengeCreator | IsOwner]
    permission_classes = [IsAuthenticated, IsChallengeCreator | IsManager]
    renderer_classes = [ChallengeCreatorRenderer]
