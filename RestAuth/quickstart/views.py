from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import permissions
from quickstart.permissions import ClientPermissions, BrokerPermissions
from .serializers import *
from quickstart.models import ACL
from RestAuth.settings import BASE_DIR

import os
import jwt


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAdminUser]


class TokenView(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated, ClientPermissions]
    keySerializer = KeyStoreSerializer
    aclSerializer = ACLSerializer
    private_key = open(os.path.join(BASE_DIR, 'ssl/.server_private.pem')).read()

    def list(self, request, *args, **kwargs):
        user_now = request.user
        jwt_payload = self.aclSerializer(ACL.objects.filter(user=user_now), many=True).data
        encoded = jwt.encode({'acl_payload': jwt_payload}, self.private_key, algorithm='RS256')
        return Response({
            'keys': self.keySerializer(KeyStore.objects.get(user=user_now)).data,
            'acl_jwt': encoded,
        })


class PublicKeyView(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated, BrokerPermissions]
    publicSerializer = PublicKeySerializer
    serverPubKey = open(os.path.join(BASE_DIR, 'ssl/.server_public.pem')).read()

    def list(self, request, *args, **kwargs):
        try:
            usrn = request.query_params.get('username')
            user_now = User.objects.get(username=usrn)
            userKey = self.publicSerializer(KeyStore.objects.get(user=user_now)).data
        except Exception as e:
            userKey = str(e)

        return Response({
            'server': self.serverPubKey,
            'client': userKey
        })


