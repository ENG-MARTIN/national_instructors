from django.contrib import admin

# Register your models here.
from .models import CustomUser

@admin.register(CustomUser)
class UserAdmin(admin.ModelAdmin):
    list_display = ('surname', 'other_names', 'email', 'phone', 'nationality')
    search_fields = ('surname', 'email', 'phone')

