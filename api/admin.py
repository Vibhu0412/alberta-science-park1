from django.contrib import admin
from .models import User, PersonalInformation, BusinessInformation, UserRole, InvitedUser, PersonalEducation\
    ,ProfessionalExperience, LanguagesSpoken,PersonalDocumentUpload, HonorsAndAwards, PersonalCertificates
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError


class UserProfileInline(admin.StackedInline):
    model = PersonalInformation
    can_delete = False


class UserAdmin(BaseUserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('id', 'username', 'email', 'can_invite_others', 'is_staff')
    list_filter = ('is_staff',)
    fieldsets = (
        ('User Credentails', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'can_invite_others')}),
        ('Permissions', {'fields': ('is_admin', 'is_challenge_creator', 'is_solution_provider', 'is_manager', 'is_staff')}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'role', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email', 'id',)
    filter_horizontal = ()
    # inlines = (UserProfileInline,)


# Now register the new UserAdmin...
admin.site.register(User, UserAdmin)
# ... and, since we're not using Django's built-in permissions,
# unregister the Group model from admin.
admin.site.unregister(Group)


class PersonalInformationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'first_name', 'last_name', 'office_phone')


class BusinessInformationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user_id', 'user','company_name', 'company_phone', 'company_classification')


class InvitedUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'invited_by', 'is_registered', 'can_invite_others','company_name')

@admin.register(PersonalEducation)
class PersonalEducationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user','school','degree','field_of_study','start_date','end_date')

@admin.register(ProfessionalExperience)
class ProfessionalExperienceAdmin(admin.ModelAdmin):
    list_display = ('id', 'user','industry','company_name','employment_type')

@admin.register(LanguagesSpoken)
class LanguagesSpokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'user','language_name','language_proficiency')

admin.site.register(PersonalInformation, PersonalInformationAdmin)
admin.site.register(BusinessInformation, BusinessInformationAdmin)
admin.site.register(UserRole)

admin.site.register(HonorsAndAwards)
admin.site.register(PersonalCertificates)

admin.site.register(PersonalDocumentUpload)
admin.site.register(InvitedUser, InvitedUserAdmin)
admin.site.site_header = "Alberta Science Park"
