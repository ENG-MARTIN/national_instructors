from django.shortcuts import render,redirect
from django.contrib import messages
from .models import Admin, Application, CustomUser
from .forms import AdminRegisterForm, RegisterForm
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import authenticate, login, get_user_model
from django.http import HttpResponseForbidden
import logging
import uuid
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
import json
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.db.models import Count
from django.views.decorators.http import require_http_methods

# Create your views here.

def apply(request):
    return redirect(request, 'apply_ditte')
# Set up logging
logger = logging.getLogger(__name__)

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "No user found with this email.")
            return render(request, 'login.html')

        if user.check_password(password):
            login(request, user)

            # Store user data in session using email only (no ID)
            request.session['user_data'] = {
                'email': user.email,
                'surname': user.surname,
                'other_names': user.other_names,
                'phone': user.phone,
                'nationality': user.nationality,
                'dob': user.dob.isoformat() if user.dob else None,
                'sex': user.sex,
            }
            return redirect('apply_ditte')
        else:
            messages.error(request, "Invalid password. Please try again.")

    return render(request, 'login.html')

def adminLogin_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = Admin.objects.get(email=email)
            if user.check_password(password):
                # Manually create session (without django.contrib.auth.login)
                request.session['admin_id'] = user.id
                request.session['admin_email'] = user.email
                request.session['admin_name'] = user.full_name
                request.session['is_admin_logged_in'] = True
                
                return redirect('admin_dashboard')
            else:
                messages.error(request, "Invalid password. Please try again.")
        except Admin.DoesNotExist:
            messages.error(request, "No admin found with this email.")

    return render(request, 'adminlogin.html')


# admin register
def register_admin(request):
    if request.method == 'POST':
        # Get data from POST request
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        role = request.POST.get('role')
        full_name = request.POST.get('full_name')
        phone_number = request.POST.get('phone_number')

        # Validation checks
        if password != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('register_admin')

        if not email or not password or not role or not full_name or not phone_number:
            messages.error(request, "All fields are required.")
            return redirect('register_admin')

        # Create and save the admin instance
        try:
            hashed_password = make_password(password)  # Hash the password before saving

            admin = Admin(
                email=email,
                password=hashed_password,
                role=role,
                full_name=full_name,
                phone_number=phone_number
            )
            admin.save()

            messages.success(request, "Admin registered successfully!")
            return redirect('adminlogin')  # Redirect to admin login page

        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('register_admin')
    else:
        return render(request, 'admin_register.html')

# 

def register(request):
    errors = None  # Initialize error variable
    
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])  # Encrypt password
            user.is_active = False  # Inactive until email verification
            user.save()
            
            messages.success(request, "Registration successful! Check your email.")
            return redirect('login')
        else:
            errors = form.errors  # Capture form errors

    else:
        form = RegisterForm()
    
    return render(request, 'register.html', {'form': form, 'errors': errors})


def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Email verified successfully! You can now log in.")
        return redirect('login')
    else:
        messages.error(request, "Invalid verification link!")
        return redirect('register')



def ditte_application(request):
    user_data = request.session.get('user_data', {})
    
    if not user_data:  # If no user data, redirect to login
        messages.error(request, "You must be logged in to access this page.")
        return redirect('login')

    # Retrieve existing applications for this user (using email from session)
    applications = Application.objects.filter(email=user_data.get('email'))

    if request.method == 'POST':
        try:
            personal_info = {
                'surname': request.POST['surname'],
                'other_names': request.POST['other_names'],
                'gender': request.POST['gender'],
                'date_of_birth': request.POST['date_of_birth'],
                'nationality': request.POST['nationality'],
                'home_district': request.POST['home_district'],
                'county': request.POST['county'],
                'sub_county': request.POST['sub_county'],
                'permanent_address': request.POST['permanent_address'],
                'phone': request.POST['phone'],
                'email': request.POST['email'],
                'marital_status': request.POST['marital_status'],
                'children': int(request.POST['children']),
                'religion': request.POST['religion']
            }

            education_backgrounds = json.loads(request.POST.get('education_backgrounds', '[]'))
            major_subjects = request.POST.get('major_subjects', '')

            employment_records = json.loads(request.POST.get('employment_records', '[]'))

            programme = request.POST['programme']
            programme_status = request.POST['programme_status']

            sponsorship = {
                'sponsor_name': request.POST['sponsor_name'],
                'sponsor_address': request.POST['sponsor_address'],
                'sponsor_phone': request.POST['sponsor_phone'],
                'sponsor_email': request.POST['sponsor_email']
            }

            application = Application(
                **personal_info,
                education_backgrounds=education_backgrounds,
                major_subjects=major_subjects,
                employment_records=employment_records,
                programme=programme,
                programme_status=programme_status,
                **sponsorship,
                status='Submitted'  # Default status for new applications
            )
            application.save()

            messages.success(request, "Application submitted successfully!")
            return redirect('apply_ditte')  # Redirect to same page to show updated list

        except KeyError as e:
            messages.error(request, f'Missing field: {str(e)}')
            return render(request, 'application_form.html', {
                'user': user_data,
                'applications': applications
            })
        
        except json.JSONDecodeError as e:
            messages.error(request, f'Incvalid JSON data: {str(e)}')
            return render(request, 'application_form.html', {
                'user': user_data,
                'applications': applications
            })
        
        except ValidationError as e:
            messages.error(request, f'Validation error: {str(e)}')
            return render(request, 'application_form.html', {
                'user': user_data,
                'applications': applications
            })

    return render(request, 'application_form.html', {
        'user': user_data,
        'applications': applications
    })


def view_application_details(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    return render(request, 'user_application_details.html', {'application': application})


def admin(request):
    if 'admin_email' not in request.session:
        return redirect('adminlogin')  # Force login if no session
    
    email = request.session['admin_email']
    
    try:
        user = Admin.objects.get(email=email)
    except Admin.DoesNotExist:
        del request.session['admin_email'] 
        return redirect('adminlogin')
    
    return render(request,'admin.html',{'user': user})

def admin_dashboard(request):
    return render(request, 'admin.html')


# View administrators View
def admin_list_view(request):
    applications = Application.objects.all()
    paginator = Paginator(applications, 10)  # Show 10 applications per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'administrators.html', {'page_obj': page_obj})

def admin_edit_view(request, pk):  # pk will be an integer
    admin = get_object_or_404(Admin, pk=pk)
    # ... rest of your edit logic


def admin_delete_view(request, pk):
    admin = get_object_or_404(Admin, pk=pk)
    # ... rest of your delete logic


# View Applications View
def view_applications(request):
    applications = Application.objects.all()
    paginator = Paginator(applications, 10)  # Show 10 applications per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'view_applications.html', {'page_obj': page_obj})

# Manage Applications View
@login_required
def manage_applications(request):
    # Fetch applications from the database (example)
    applications = [
        {'id': 1, 'name': 'Application 1', 'status': 'Pending'},
        {'id': 2, 'name': 'Application 2', 'status': 'Approved'},
    ]
    return render(request, 'manage_applications.html', {'applications': applications})

# User Management View
# @login_required
def user_management(request):
    # Fetch all users from the CustomUser model
    users = CustomUser.objects.all()
    return render(request, 'user_management.html', {'users': users})

# Admin Management View
def admin_management(request):
    users = Admin.objects.all()
    return render(request, 'administrators.html', {'users': users})


# Reports View
# @login_required
def reports(request):
    applications = Application.objects.all()
    
    # Status statistics
    status_stats = applications.values('status').annotate(count=Count('status'))
    status_choices = dict(Application.STATUS_CHOICES)
    
    programme_stats = applications.values('programme').annotate(count=Count('programme'))
    programme_choices = dict(Application._meta.get_field('programme').choices)
    
    gender_stats = applications.values('gender').annotate(count=Count('gender'))
    
    recent_applications = applications.order_by('-id')[:5]
    
    programme_status_stats = applications.values('programme_status').annotate(count=Count('programme_status'))
    
    context = {
        'total_applications': applications.count(),
        'status_stats': {stat['status']: stat['count'] for stat in status_stats},
        'status_choices': status_choices,
        'programme_stats': {stat['programme']: stat['count'] for stat in programme_stats},
        'programme_choices': programme_choices,
        'gender_stats': {stat['gender']: stat['count'] for stat in gender_stats},
        'programme_status_stats': {stat['programme_status']: stat['count'] for stat in programme_status_stats},
        'recent_applications': recent_applications,
    }
    return render(request, 'reports.html', context)

# ----------------------------------------  this is editing the application on admin       -----------
@csrf_exempt
def get_application(request, pk):
    try:
        application = Application.objects.get(pk=pk)
        return JsonResponse({
            'endorser_name': application.endorser_name,
            'endorser_designation': application.endorser_designation,
            'endorser_institution': application.endorser_institution,
            'endorser_address': application.endorser_address
        })
    except Application.DoesNotExist:
        return JsonResponse({'error': 'Application not found'}, status=404)

@csrf_exempt
def update_endorser_details(request):
    if request.method == 'POST':
        try:
            application = Application.objects.get(pk=request.POST.get('application_id'))
            application.endorser_name = request.POST.get('endorser_name', '')
            application.endorser_designation = request.POST.get('endorser_designation', '')
            application.endorser_institution = request.POST.get('endorser_institution', '')
            application.endorser_address = request.POST.get('endorser_address', '')
            application.save()
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=400)
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=400)

# Settings View
@login_required
def settings(request):
    # Fetch settings data from the database (example)
    settings = [
        {'id': 1, 'name': 'Setting 1', 'value': 'Enabled'},
        {'id': 2, 'name': 'Setting 2', 'value': 'Disabled'},
    ]
    return render(request, 'settings.html', {'settings': settings})

# Profile View
@login_required
def profile(request):
    # Fetch the current user's profile data (example)
    user = request.user
    profile_data = {
        'username': user.username,
        'email': user.email,
        'role': 'Admin' if user.is_superuser else 'Staff',
    }
    return render(request, 'profile.html', {'profile': profile_data})

def edit_application(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    if request.method == 'POST':
        form = ApplicationForm(request.POST, instance=application)
        if form.is_valid():
            form.save()
            return redirect('view_applications')
    else:
        form = ApplicationForm(instance=application)
    return render(request, 'edit_application.html', {'form': form})

#   =======================user dashboard================
def profile_view(request):
    user = request.user
    applications = Application.objects.filter(email=user.email)
    return render(request, 'application_form.html', {'applications': applications})

def get_applications_by_email(request):
    if request.method == 'GET' and 'email' in request.GET:
        email = request.GET['email']
        applications = Application.objects.filter(email=email).values(
            'id', 'surname', 'other_names', 'programme', 'status', 'submission_date'
        )
        applications_list = list(applications)  # Convert QuerySet to list
        return JsonResponse(applications_list, safe=False)
    return JsonResponse({'error': 'Invalid request'}, status=400)