from django.urls import path, include
from rest_framework import routers
from .views import SolutionInformationViewSet


router = routers.DefaultRouter()
router.register(r'solution-profile', SolutionInformationViewSet)

urlpatterns = [
    path('', include(router.urls)),
]

