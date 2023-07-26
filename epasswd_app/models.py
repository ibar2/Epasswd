from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):

    def __str__(self) -> str:
        return self.username


class passwords(models.Model):
    """
    The encrypted password would split between this model and the partialpass
    model but this model would contain the most amount of the informations of the
    passwords.
    The owner field is integerfield and not foreign because the owner and passwords model
    wouldn't be in the same database
    """

    owner = models.IntegerField()
    name = models.CharField(max_length=55, unique=True)
    passwd = models.BinaryField()
    tag = models.BinaryField()
    nonce = models.BinaryField()
    created_at = models.DateField(auto_now=True)


class partialpass(models.Model):
    """
    This model saves the remaining half of the encrypted password.
    The reason why we use the Integerfield and not the foreign key 
    is the models wouldn't be saved in the same database so to connected them
    we faced some issue there could be some tweeks but i think this is the best 
    and easiest possible
    """
    partof = models.IntegerField()
    partial = models.BinaryField()
    owner = models.IntegerField(default=None)


class hashers(models.Model):
    """
    stores a ecryption key for the user
    1 encryption key for 1 user
    and hashers model and users may not be saved in the same database
    """

    userpk = models.IntegerField()
    key = models.BinaryField()
