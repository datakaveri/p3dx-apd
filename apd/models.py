from django.db import models

# Create your models here.

class Userclass(models.Model):
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=200)

# class Evaluation(models.Model):
# need this also for successful and failed (?) evaluations
