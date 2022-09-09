from django.urls import path, include
from rest_framework import routers
from .views import ChallengeStatementViewSet, CommentApiView,PushArchieveApiView,PushUnArchieveApiView

router = routers.DefaultRouter()
router.register(r'challenge', ChallengeStatementViewSet, basename='challenge')
# router.register(r'comment', CommentViewSet)geStatementViewSet, basename='challenge')

urlpatterns = [
    path('comment', CommentApiView.as_view(), name='comment-list'),
    path('comment/<int:pk>', CommentApiView.as_view(), name='post-comment'),
    path('challenge/push-archieve/<int:pk>', PushArchieveApiView.as_view(), name='push-archieve'),
    path('challenge/un-archieve/<int:pk>', PushUnArchieveApiView.as_view(), name='un-archieve'),
]
urlpatterns+=router.urls

