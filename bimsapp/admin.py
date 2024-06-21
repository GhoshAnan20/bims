from django.contrib import admin
from bimsapp.models import *
from bimsapp.forms import *
from django.contrib.auth.models import User


class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'desc', 'date')
    list_per_page = 5
    search_fields = ('name',)


class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_verified', 'create_at')
    list_per_page = 5
   

class FormAdmin(admin.ModelAdmin):
    list_display = ('firstName', 'lastName', 'dob', 'gender', 'fatherName', 'motherName')
    list_per_page = 5
    search_fields = ('firstName', 'lastName')

class DocumentAdmin(admin.ModelAdmin):
    list_display = ('is_verified', 'title', 'date', 'file', 'uploaded_by')
    list_per_page = 5
    list_filter = ('title', 'uploaded_by')

# Register your models here.
admin.site.register(Contact, ContactAdmin)
admin.site.register(Profile, ProfileAdmin)
admin.site.register(Form, FormAdmin)
admin.site.register(Document, DocumentAdmin)
admin.site.register(Upload)
