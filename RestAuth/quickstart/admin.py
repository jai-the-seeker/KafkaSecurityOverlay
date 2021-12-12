from django.contrib import admin

# Register your models here.
from quickstart.models import ACL, KeyStore

admin.site.register(ACL)
admin.site.register(KeyStore)