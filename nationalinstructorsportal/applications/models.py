from django.db import models
# from . import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid

# Create your models here.

class Application(models.Model):
    # Step 1: Personal Information
    surname = models.CharField(max_length=100)
    other_names = models.CharField(max_length=100)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    date_of_birth = models.DateField()
    nationality = models.CharField(max_length=100)
    home_district = models.CharField(max_length=100)
    county = models.CharField(max_length=100)
    sub_county = models.CharField(max_length=100)
    permanent_address = models.CharField(max_length=255)
    phone = models.CharField(max_length=15)
    email = models.EmailField()
    marital_status = models.CharField(max_length=10, choices=[
        ('single', 'Single'),
        ('married', 'Married'),
        ('divorced', 'Divorced'),
        ('widowed', 'Widowed')
    ])
    children = models.IntegerField()
    religion = models.CharField(max_length=100)

    # Step 2: Education Background
    education_backgrounds = models.JSONField(default=list)  # Store as a list of dictionaries
    major_subjects = models.CharField(max_length=255)

    # Step 3: Employment Record
    employment_records = models.JSONField(default=list)  # Store as a list of dictionaries

    # Step 4: Programme and Specialisation
    programme = models.CharField(max_length=255, choices=[
        ('Agricultural Production', 'Agricultural Production'),
        ('Automobile Engineering', 'Automobile Engineering'),
        ('Civil and Building Engineering', 'Civil and Building Engineering'),
        ('Electrical Engineering', 'Electrical Engineering'),
        ('Leather Tanning & Leather Goods Production', 'Leather Tanning & Leather Goods Production'),
        ('Metal Fabrication', 'Metal Fabrication'),
        ('Tailoring and Garments Design', 'Tailoring and Garments Design')
    ])
    programme_status = models.CharField(max_length=50, choices=[
        ('Full Time Government (1 Year)', 'Full Time Government (1 Year)'),
        ('Full Time Private (1 Year)', 'Full Time Private (1 Year)')
    ])
    STATUS_CHOICES = [
        ('Submitted', 'Submitted'),  # Default status when application is created
        ('Pending', 'Pending'),      # Under review
        ('Admitted', 'Admitted'),    # Accepted
        ('Declined', 'Declined'),    # Rejected
    ]
    
    # ... (keep all your existing fields) ...
    
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='Submitted'  # Default status when new application is created
    )

    # Step 5: Sponsorship
    sponsor_name = models.CharField(max_length=255)
    sponsor_address = models.CharField(max_length=255)
    sponsor_phone = models.CharField(max_length=15)
    sponsor_email = models.EmailField()

    # Step 6: Declaration (left null for admin to fill later)
    declaration_signature = models.CharField(max_length=255, null=True, blank=True)
    endorser_name = models.CharField(max_length=255, null=True, blank=True)
    endorser_designation = models.CharField(max_length=255, null=True, blank=True)
    endorser_institution = models.CharField(max_length=255, null=True, blank=True)
    endorser_address = models.CharField(max_length=255, null=True, blank=True)
    endorser_signature = models.CharField(max_length=255, null=True, blank=True)
    official_stamp = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"{self.surname} {self.other_names}"

# -----------------====================user registration=======================

class CustomUserManager(BaseUserManager):
    def create_user(self, email, surname, other_names, phone, nationality, dob, sex, password=None):
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            surname=surname,
            other_names=other_names,
            phone=phone,
            nationality=nationality,
            dob=dob,
            sex=sex
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, surname, other_names, phone, nationality, dob, sex, password=None):
        user = self.create_user(email, surname, other_names, phone, nationality, dob, sex, password)
        user.is_admin = True
        user.is_active = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    surname = models.CharField(max_length=100)
    other_names = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    nationality = models.CharField(max_length=50)
    dob = models.DateField()
    sex = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female')])
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['surname', 'other_names', 'phone', 'nationality', 'dob', 'sex']

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.surname} {self.other_names}"

    def get_short_name(self):
        return self.surname

    @property
    def is_staff(self):
        return self.is_admin