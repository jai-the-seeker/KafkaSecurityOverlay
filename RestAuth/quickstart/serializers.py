from django.contrib.auth.models import User, Group
from quickstart.models import KeyStore, ACL
from rest_framework import serializers


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'groups']


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']


class KeyStoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = KeyStore
        fields = ['public_key', 'private_key']


class PublicKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = KeyStore
        fields = ['public_key']


class ACLSerializer(serializers.ModelSerializer):
    class Meta:
        model = ACL
        fields = ['topic', 'producer', 'consumer']
