from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Contact(models.Model):
    name = models.CharField(max_length=122)
    email = models.CharField(max_length=122)
    desc = models.TextField()
    date = models.DateField()

    def __str__(self):
        return self.name
    
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    auth_token = models.CharField(max_length=100)
    is_verified = models.BooleanField(default=False)
    create_at = models.DateTimeField(auto_now_add=True)
    forgot_password_token = models.CharField(max_length=100)

    def __str__(self):
        return self.user.username
    
class Form(models.Model):
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    )

    firstName = models.CharField(max_length=122)
    middleName = models.CharField(max_length=122)
    lastName = models.CharField(max_length=122)
    dob = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    motherName = models.CharField(max_length=122)
    fatherName = models.CharField(max_length=122)
    aadhaarNumber = models.BigIntegerField()
    panNumber = models.CharField(max_length=10)

    def __str__(self):
        return self.firstName + self.lastName

class Document(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='upload/')
    date = models.DateField()
    is_verified = models.BooleanField(default=False)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    transaction_id=models.CharField(max_length=255, null=True, blank=True)

def __str__(self):
        return f"{self.title}"
    
    
class Upload(models.Model):
    title = models.CharField(max_length=120)
    tesseract_output = models.TextField()
    date = models.DateField()

    def __str__(self):
        return self.title
