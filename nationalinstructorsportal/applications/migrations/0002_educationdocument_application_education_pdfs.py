# Generated by Django 5.1.7 on 2025-04-05 16:53

import applications.models
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='EducationDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pdf_file', models.FileField(upload_to=applications.models.education_pdf_upload_path)),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('application', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='applications.application')),
            ],
        ),
        migrations.AddField(
            model_name='application',
            name='education_pdfs',
            field=models.ManyToManyField(blank=True, related_name='application_pdfs', to='applications.educationdocument'),
        ),
    ]
