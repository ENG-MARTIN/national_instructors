from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views

urlpatterns = [
      path('', views.login_view, name='login'),
      path('register/', views.register, name='register'),
      path('adminlogin/', views.login_view, name='adminlogin'),
      path('register-admin/', views.register_admin, name='register_admin'),

      
      path('upload-academic-document/', views.upload_academic_document, name='upload_academic_document'),
      path('get_application_details/<int:app_id>/', views.get_application_details, name='get_application_details'),
      path('view-applications/view_documents/', views.view_academic_documents, name='view_documents'),


      path('verify/<uidb64>/<token>/', views.verify_email, name='verify_email'),

      path('apply/', views.ditte_application, name='apply_ditte'),
      path('application/<int:application_id>/', views.view_application_details, name='view_application_details'),

      path('administrator/', views.admin, name="admin"),
      path('admin-dashboard/', views.admin_dashboard, name='c'),
      path('view-applications/', views.view_applications, name='view_applications'),
      path('manage-applications/', views.manage_applications, name='manage_applications'),
      path('user-management/', views.user_management, name='user_management'),
      path('admin-management/', views.admin_management, name='admin_list'),
      path('api/applications/<int:pk>/', views.get_application, name='get_application'),
      # path('api/applications/<int:pk>/update/', views.u pdate_application, name='update_application'),
      path('update_endorser_details/', views.update_endorser_details, name='update_endorser_details'),

      path('reports/', views.reports, name='reports'),
      path('profile/', views.profile, name='profile'),

      path('edit-application/<int:application_id>/', views.edit_application, name='edit_application'),

# 
     path('upload/', views.upload_testimonial, name='upload_testimonial'),
 path('success/<int:pk>/', views.upload_success, name='upload_success'),      # =========================
      path('get-applications/', views.get_applications_by_email, name='get_applications_by_email'),
      path('admin/edit/<int:pk>/', views.admin_edit_view, name='admin_edit'),  # Note <int:pk>
      path('admin/delete/<int:pk>/', views.admin_delete_view, name='admin_delete'),  # Note <int:pk>
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
