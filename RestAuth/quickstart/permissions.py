from rest_framework import permissions
from django.contrib.auth.models import User, Group


class ClientPermissions(permissions.BasePermission):
    message = "you are not a client"

    def has_permission(self, request, view):
        user_now = request.user
        if request.method in permissions.SAFE_METHODS:
            return user_now.groups.filter(name='client').exists()
        else:
            return False


class BrokerPermissions(permissions.BasePermission):
    message = "you are not a broker overlay"

    def has_permission(self, request, view):
        user_now = request.user
        if request.method in permissions.SAFE_METHODS:
            return user_now.groups.filter(name='broker_overlay').exists()
        else:
            return False
