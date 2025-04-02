from django import forms
from .models import Admin, Application
from .models import CustomUser
from django.contrib.auth.forms import UserCreationForm


class DITTEApplicationForm(forms.ModelForm):
    class Meta:
        model = Application
        fields = '__all__'
        widgets = {
            'surname': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your surname'}),
            'other_names': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter other names'}),
            'gender': forms.Select(attrs={'class': 'form-select'}),
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'nationality': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter nationality'}),
            'home_address': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter home address'}),
            'permanent_address': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter permanent address'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter phone number'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter email'}),
            'marital_status': forms.Select(attrs={'class': 'form-select'}),
            'children': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter number of children'}),
            'religion': forms.Select(attrs={'class': 'form-select'}),
            'next_of_kin': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter next of kin details'}),
            'education_background': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter education background'}),
            'major_subjects': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter major subjects'}),
            'employment_record': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter employment record'}),
            'programme': forms.Select(attrs={'class': 'form-select'}),
            'programme_status': forms.Select(attrs={'class': 'form-select'}),
            'sponsor_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter sponsor name'}),
            'sponsor_address': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter sponsor address'}),
            'sponsor_phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter sponsor phone'}),
            'sponsor_email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter sponsor email'}),
            'declaration_signature': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your signature'}),
            'endorser_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter endorser name'}),
            'endorser_designation': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter endorser designation'}),
            'endorser_institution': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter endorser institution'}),
            'endorser_address': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter endorser address'}),
            'endorser_signature': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter endorser signature'}),
            'official_stamp': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter official stamp'}),
        }



# =============================== registratiopn form  ==================
class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, label="Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput, label="Confirm Password")

    class Meta:
        model = CustomUser
        fields = ['surname', 'other_names', 'email', 'phone', 'nationality', 'dob', 'sex', 'password']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match!")

        return cleaned_data
    

    # admin register

class AdminRegisterForm(UserCreationForm):
    email = forms.EmailField()
    role = forms.CharField(max_length=50)
    full_name = forms.CharField(max_length=100)
    phone_number = forms.CharField(max_length=15)

    class Meta:
        model = Admin
        fields = ['email', 'password1', 'password2', 'role', 'full_name', 'phone_number']
