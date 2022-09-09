from django.contrib import admin
from .models import ChallengeStatement, Industry, Comment


# Register your models here.
class ChallengeStatementAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'challenge_title', 'challenge_location', 'post_type','status_type',)
    list_display_links = ('id', 'user',)
    list_filter = ('status_type', )


admin.site.register(ChallengeStatement, ChallengeStatementAdmin)
admin.site.register(Industry)
admin.site.register(Comment)
