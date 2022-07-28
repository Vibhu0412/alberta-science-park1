from django.contrib import admin
from .models import User, PersonalInformation, BusinessInformation, UserRole
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
    list_display = ('id', 'username', 'email', 'is_staff')
    list_filter = ('is_staff',)
    fieldsets = (
        ('User Credentails', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'role',)}),
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
    list_display = ('id', 'user', 'first_name', 'last_name', 'office_phone', 'education', 'position')


class BusinessInformationAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'company_name', 'company_phone', 'company_classification')


admin.site.register(PersonalInformation, PersonalInformationAdmin)
admin.site.register(BusinessInformation, BusinessInformationAdmin)
admin.site.register(UserRole)
admin.site.site_header = "Alberta Science Park"
