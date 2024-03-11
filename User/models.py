from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class UserData(models.Model):
    user_name = models.ForeignKey(User, on_delete=models.CASCADE)
    plug = models.CharField(max_length=20)
    #AccNumber = models.IntegerField()
    Reflactorr = models.CharField(max_length=100)
    Router1 = models.CharField(max_length=100)
    Router2 = models.CharField(max_length=100)
    Router3 = models.CharField(max_length=100)
    notch1= models.CharField(max_length=10, default=None, null=True)
    notch2= models.CharField(max_length=10, default=None, null=True)
    notch3= models.CharField(max_length=10, default=None, null=True)
    key= models.CharField(max_length=10)
    ring= models.CharField(max_length=10)
    specialch=models.CharField(max_length=8)


class savesPass(models.Model):
    user_name = models.ForeignKey(User, on_delete=models.CASCADE)
    URL = models.CharField(max_length=100)
    PassWord = models.CharField(max_length=32)