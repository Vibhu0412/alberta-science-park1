from django.urls import path
from rest_framework_simplejwt import views as jwt_views

from .views import UserRegistrationView, UserLoginView, UserChangePasswordView, \
    SendPasswordResetEmailView, UserPasswordResetView, PersonalProfileCreateView, PersonalProfileUpdateView, \
    BusinessProfileCreateView, BusinessProfileUpdateView, RoleRegisterView, SendInviteLinkView, FetchInvitedUserView, \
    FetchCompanyApiView, InviteNotificationApiView

urlpatterns = [
    path('token/obtain/', jwt_views.TokenObtainPairView.as_view(), name='token_create'),
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),

    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),

    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),

    path('create/personal-profile/', PersonalProfileCreateView.as_view(), name='create-personal-profile'),
    path('update/personal-profile/<int:pk>/', PersonalProfileUpdateView.as_view(), name='update-personal-profile'),

    path('create/business-profile/', BusinessProfileCreateView.as_view(), name='create-business-profile'),
    path('update/business-profile/<int:pk>/', BusinessProfileUpdateView.as_view(), name='update-business-profile'),
    path('delete/business-profile/<int:pk>/', BusinessProfileUpdateView.as_view(), name='delete-business-profile'),

    path('upgrade-role/<int:pk>/', RoleRegisterView.as_view(), name='upgrade-role'),

    path('send-invitation-link/', SendInviteLinkView.as_view(), name='send-invitation-link'),
    path('edit-invitation-link/<int:pk>/', SendInviteLinkView.as_view(), name='edit-invitation-link'),
    path('delete-invitation-link/<int:pk>/', SendInviteLinkView.as_view(), name='delete-invitation-link'),

    path('invited-users/', FetchInvitedUserView.as_view(), name='get-invited-users'),

    path('company/', FetchCompanyApiView.as_view(), name='company'),

    path('invite-notification/', InviteNotificationApiView.as_view(), name='notification'),
    path('invite-notification/<int:pk>', InviteNotificationApiView.as_view(), name='notification')

]
