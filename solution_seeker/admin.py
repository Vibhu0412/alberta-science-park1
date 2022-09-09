from django.contrib import admin
from .models import SolutionInformationProfile


# Register your models here.
class SolutionInformationProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'solution_user_title', 'skills', 'experience_level',)
    list_display_links = ('id', 'user',)


admin.site.register(SolutionInformationProfile, SolutionInformationProfileAdmin)
