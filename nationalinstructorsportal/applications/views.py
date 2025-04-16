from django.shortcuts import render,redirect
from django.contrib import messages
from .models import AcademicDocument, Admin, Application, CustomUser, EducationDocument, EducationImage, StudentTestimonial
from .forms import AdminRegisterForm, PaymentForm, RegisterForm, StudentTestimonialForm
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
import os
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password
from django.db.models import Count
from django.views.decorators.http import require_http_methods
from django.db.models import Q 
from django.contrib.auth import login as auth_login
from django.views.generic import ListView   
from django.core.paginator import Paginator


# Create your views here.

def apply(request):
    return redirect(request, 'apply_ditte')
logger = logging.getLogger(__name__)

def login_view(request):
    next_url = request.GET.get('next', '')  # Get the next URL if it exists
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        next_url = request.POST.get('next', '')  # Get next from POST if submitted
        
        # Try admin first
        try:
            admin = Admin.objects.get(email=email)
            if admin.check_password(password):
                # Admin login successful
                request.session['admin_id'] = admin.id
                request.session['admin_email'] = admin.email
                request.session['admin_name'] = admin.full_name
                request.session['is_admin_logged_in'] = True
                return redirect(next_url if next_url else 'admin_dashboard')
            else:
                messages.error(request, "Invalid password. Please try again.")
        except Admin.DoesNotExist:
            pass  # Proceed to check regular users
        
        # Try regular user
        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                if user.is_active:
                    # Regular user login successful
                    auth_login(request, user)  # Use Django's login function
                    request.session['user_data'] = {
                        'email': user.email,
                        'surname': user.surname,
                        'other_names': user.other_names,
                        'phone': user.phone,
                        'nationality': user.nationality,
                        'dob': user.dob.isoformat() if user.dob else None,
                        'sex': user.sex,
                    }
                    return redirect(next_url if next_url else 'apply_ditte')
                else:
                    messages.error(request, "Your account is not active. Please contact support.")
            else:
                messages.error(request, "Invalid password. Please try again.")
        except User.DoesNotExist:
            messages.error(request, "No account found with this email.")
    
    # For GET requests or failed logins
    return render(request, 'login.html', {'next': next_url})


def adminLogin_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = Admin.objects.get(email=email)
            if user.check_password(password):
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
        full_name = request.POST.get('full_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        role = request.POST.get('role')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')        
        if password1 != password2:
            messages.error(request, "Passwords don't match")
            return redirect('register_admin')
        
        if Admin.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered')
            return redirect('register_admin')            
        if Admin.objects.filter(phone_number=phone_number).exists():
            messages.error(request, 'Phone number already registered')
            return redirect('register_admin')
            
        if Admin.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken')
            return redirect('register_admin')
        
        try:
            admin = Admin.objects.create(
                full_name=full_name,
                username=username,
                email=email,
                phone_number=phone_number,
                role=role,
                password=make_password(password1)
            )
        
            messages.success(request, 'Registration successful! Please login.')
            return redirect('adminlogin')
            
        except Exception as e:
            messages.error(request, f'Error during registration: {str(e)}')
    
    return render(request, 'admin_register.html')


def register(request):
    errors = None    
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])  
            user.is_active = True  # Change this to True
            user.save()
            
            messages.success(request, "Registration successful!")
            return redirect('login')
        else:
            errors = form.errors  
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

@login_required
def ditte_application(request):
    user_data = request.session.get('user_data', {})
    
    if not user_data:
        messages.error(request, "You must be logged in to access this page.")
        return redirect('login')

    applications = Application.objects.filter(email=user_data.get('email'))

    if request.method == 'POST':
        try:
            print("Starting application processing...")  # Debug print
            
            # Process personal info
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
                'religion': request.POST['religion']
            }
            print("Personal info processed successfully")  # Debug print

            # Process education and employment data
            education_backgrounds = json.loads(request.POST.get('education_backgrounds', '[]'))
            major_subjects = request.POST.get('major_subjects', '')
            employment_records = json.loads(request.POST.get('employment_records', '[]'))
            programme = request.POST['programme']
            programme_status = request.POST['programme_status']
            print("Education/employment data processed successfully")  # Debug print

            # Process sponsorship data
            sponsorship = {
                'sponsor_name': request.POST['sponsor_name'],
                'sponsor_address': request.POST['sponsor_address'],
                'sponsor_phone': request.POST['sponsor_phone'],
                'sponsor_email': request.POST['sponsor_email']
            }
            print("Sponsorship data processed successfully")  # Debug print

            # Create and save application
            application = Application(
                **personal_info,
                education_backgrounds=education_backgrounds,
                major_subjects=major_subjects,
                employment_records=employment_records,
                programme=programme,
                programme_status=programme_status,
                **sponsorship,
                status='Submitted'
            )
            application.save()
            print(f"Application saved successfully with ID: {application.id}")  # Debug print

            # Handle PNG image uploads with detailed logging
            if 'education_image' in request.FILES:
                print("Found image files in request")  # Debug print
                fs = FileSystemStorage()
                image_files = request.FILES.getlist('education_image')
                print(f"Found {len(image_files)} image files to process")  # Debug print
                
                if len(image_files) > 5:  # Limit to 5 files
                    msg = "Maximum of 5 PNG images allowed. Only the first 5 were uploaded."
                    messages.warning(request, msg)
                    print(msg)  # Debug print
                    image_files = image_files[:5]
                
                saved_images = 0
                for idx, image_file in enumerate(image_files, 1):
                    try:
                        print(f"\nProcessing image {idx}/{len(image_files)}: {image_file.name}")  # Debug print
                        print(f"File size: {image_file.size} bytes")  # Debug print
                        
                        # Validate file size (2MB limit)
                        if image_file.size > 2 * 1024 * 1024:
                            msg = f"Image {image_file.name} exceeds 2MB limit and was not uploaded."
                            messages.warning(request, msg)
                            print(msg)  # Debug print
                            continue
                        
                        # Validate file extension
                        if not image_file.name.lower().endswith('.png'):
                            msg = f"File {image_file.name} is not a PNG image and was not uploaded."
                            messages.warning(request, msg)
                            print(msg)  # Debug print
                            continue
                        
                        # Create a unique filename to prevent overwrites
                        filename = f"edu_img_{application.id}_{uuid.uuid4().hex[:8]}_{image_file.name}"
                        print(f"Generated unique filename: {filename}")  # Debug print
                        
                        # Save the image
                        print("Creating EducationImage instance...")  # Debug print
                        education_image = EducationImage(application=application)
                        print("Saving image file...")  # Debug print
                        education_image.image_file.save(filename, image_file)
                        education_image.original_filename = image_file.name
                        education_image.save()
                        saved_images += 1
                        
                        print(f"Successfully saved image {image_file.name} with ID: {education_image.id}")  # Debug print
                        print(f"Image path: {education_image.image_file.path}")  # Debug print
                        print(f"Image URL: {education_image.image_file.url}")  # Debug print
                        
                    except Exception as e:
                        error_msg = f"Error processing {image_file.name}: {str(e)}"
                        messages.error(request, error_msg)
                        print(error_msg)  # Debug print
                        import traceback
                        traceback.print_exc()  # Print full traceback

                if saved_images > 0:
                    success_msg = f"Successfully uploaded {saved_images} PNG image(s)"
                    messages.success(request, success_msg)
                    print(success_msg)  # Debug print

            # Final success message
            success_msg = "Application submitted successfully!"
            messages.success(request, success_msg)
            print(success_msg)  # Debug print
            print(f"Application ID {application.id} has {application.education_images.count()} images")  # Debug print
            
            return redirect('apply_ditte')

        except KeyError as e:
            error_msg = f'Missing required field: {str(e)}'
            messages.error(request, error_msg)
            print(error_msg)  # Debug print
        except json.JSONDecodeError as e:
            error_msg = f'Invalid JSON data: {str(e)}'
            messages.error(request, error_msg)
            print(error_msg)  # Debug print
        except ValidationError as e:
            error_msg = f'Validation error: {str(e)}'
            messages.error(request, error_msg)
            print(error_msg)  # Debug print
        except Exception as e:
            error_msg = f'An unexpected error occurred: {str(e)}'
            messages.error(request, error_msg)
            print(error_msg)  # Debug print
            import traceback
            traceback.print_exc()  # Print full traceback
            
            # Clean up any partially saved files if needed
            if 'application' in locals():
                print("Attempting to clean up partially saved application...")  # Debug print
                try:
                    image_count = application.education_images.count()
                    print(f"Deleting {image_count} associated images...")  # Debug print
                    application.education_images.all().delete()
                    print("Deleting application...")  # Debug print
                    application.delete()
                    print("Cleanup completed successfully")  # Debug print
                except Exception as cleanup_error:
                    print(f"Error during cleanup: {str(cleanup_error)}")  # Debug print

    return render(request, 'application_form.html', {
        'user': user_data,
        'applications': applications
    })



def view_application_details(request, application_id):
    application = get_object_or_404(Application, id=application_id)
    return render(request, 'user_application_details.html', {'application': application})


def admin(request):
    if 'admin_email' not in request.session:
        return redirect('adminlogin')     
    email = request.session['admin_email']
    try:
        user = Admin.objects.get(email=email)
    except Admin.DoesNotExist:
        del request.session['admin_email'] 
        return redirect('adminlogin')
    
    return render(request,'admin.html',{'user': user})

@login_required
def admin_dashboard(request):
    return render(request, 'admin.html')

def admin_list_view(request):
    applications = Application.objects.all()
    paginator = Paginator(applications, 10) 
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'administrators.html', {'page_obj': page_obj})

def admin_edit_view(request, pk):  
    admin = get_object_or_404(Admin, pk=pk)

def admin_delete_view(request, pk):
    admin = get_object_or_404(Admin, pk=pk)
    

# View Applications View
def view_applications(request):
    applications = Application.objects.all()
    paginator = Paginator(applications, 10)  
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'view_applications.html', {'page_obj': page_obj})

# Manage Applications View
@login_required
def manage_applications(request):
    applications = [
        {'id': 1, 'name': 'Application 1', 'status': 'Pending'},
        {'id': 2, 'name': 'Application 2', 'status': 'Approved'},
    ]
    return render(request, 'manage_applications.html', {'applications': applications})

# User Management View
def user_management(request):
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


def upload_academic_document(request):
    if request.method == 'POST':
        try:
            # Get form data
            surname = request.POST.get('surname')
            other_names = request.POST.get('other_names')
            email = request.POST.get('email')
            
            # Handle file upload
            if 'academic_document' in request.FILES:
                academic_doc = request.FILES['academic_document']
                
                # Save to AcademicDocument model
                document = AcademicDocument.objects.create(
                    surname=surname,
                    other_names=other_names,
                    email=email,
                    document=academic_doc
                )
                
                return JsonResponse({
                    'success': True,
                    'message': 'Document uploaded successfully!',
                    'document_id': document.id
                })
            
            return JsonResponse({'success': False, 'error': 'No file provided'})
        
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

logger = logging.getLogger(__name__)

def get_application_details(request, app_id):
    try:
        application = Application.objects.get(id=app_id)
        from django.core.exceptions import ObjectDoesNotExist

        # Get matching documents
        documents = AcademicDocument.objects.filter(
            email=application.email,
            surname=application.surname,
            other_names=application.other_names
        )
        
        document_list = []
        for doc in documents:
            try:
                document_list.append({
                    'id': doc.id,
                    'name': f"Academic Document {doc.id}",
                    'type': 'Academic Certificate',
                    'url': doc.document.url if doc.document else '#',
                    'uploaded_at': doc.uploaded_at.strftime("%Y-%m-%d %H:%M")
                })
            except Exception as e:
                logger.error(f"Error processing document {doc.id}: {str(e)}")
                continue
        
        return JsonResponse({
            'success': True,
            'contact': application.phone_number or 'N/A',
            'qualification': application.highest_qualification or 'N/A',
            'institution': application.institution or 'N/A',
            'year_completed': application.year_completed or 'N/A',
            'start_date': application.start_date.strftime("%Y-%m-%d") if application.start_date else 'N/A',
            'endorser_name': application.endorser_name or 'N/A',
            'endorser_designation': application.endorser_designation or 'N/A',
            'endorser_institution': application.endorser_institution or 'N/A',
            'endorser_address': application.endorser_address or 'N/A',
            'documents': document_list
        })
        
    except ObjectDoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Application not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error fetching application details: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Internal server error'
        }, status=500)

def view_academic_documents(request):
    documents = AcademicDocument.objects.all().order_by('-uploaded_at')
    return render(request, 'view_pdf.html', {'documents': documents})

def upload_testimonial(request):
    if request.method == 'POST':
        form = StudentTestimonialForm(request.POST, request.FILES)
        if form.is_valid():
            saved_instance = form.save()
            return redirect('upload_success', pk=saved_instance.pk)
    else:
        form = StudentTestimonialForm()
    return render(request, 'test.html', {'form': form})

def upload_success(request, pk):
    testimonial = get_object_or_404(StudentTestimonial, pk=pk)
    return render(request, 'success.html', {'testimonial': testimonial})


# =====================receipts 
def upload_receipt(request):
    if request.method == 'POST':
        form = PaymentForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('success_page')  # Replace with your success URL
    else:
        form = PaymentForm()
    
    return render(request, 'payment/upload.html', {'form': form})