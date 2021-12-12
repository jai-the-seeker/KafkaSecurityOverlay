from django.db import models

# Create your models here.
from django.contrib.auth.models import User


class KeyStore(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    private_key = models.TextField()

    def __str__(self):
        return self.user.username


class ACL(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    topic = models.CharField(max_length=255)
    producer = models.BooleanField()
    consumer = models.BooleanField()

    def __str__(self):
        return self.user.__str__() + ':' + self.topic.__str__()
