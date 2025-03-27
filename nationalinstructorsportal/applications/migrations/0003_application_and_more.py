# Generated by Django 5.1.7 on 2025-03-20 11:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('applications', '0002_personalinfo_employmentrecord_educationbackground_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Application',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('surname', models.CharField(max_length=100)),
                ('other_names', models.CharField(max_length=100)),
                ('gender', models.CharField(choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], max_length=10)),
                ('date_of_birth', models.DateField()),
                ('nationality', models.CharField(max_length=100)),
                ('home_district', models.CharField(max_length=100)),
                ('county', models.CharField(max_length=100)),
                ('sub_county', models.CharField(max_length=100)),
                ('permanent_address', models.CharField(max_length=255)),
                ('phone', models.CharField(max_length=15)),
                ('email', models.EmailField(max_length=254)),
                ('marital_status', models.CharField(choices=[('single', 'Single'), ('married', 'Married'), ('divorced', 'Divorced'), ('widowed', 'Widowed')], max_length=10)),
                ('children', models.IntegerField()),
                ('religion', models.CharField(max_length=100)),
                ('education_backgrounds', models.JSONField(default=list)),
                ('major_subjects', models.CharField(max_length=255)),
                ('employment_records', models.JSONField(default=list)),
                ('programme', models.CharField(choices=[('Agricultural Production', 'Agricultural Production'), ('Automobile Engineering', 'Automobile Engineering'), ('Civil and Building Engineering', 'Civil and Building Engineering'), ('Electrical Engineering', 'Electrical Engineering'), ('Leather Tanning & Leather Goods Production', 'Leather Tanning & Leather Goods Production'), ('Metal Fabrication', 'Metal Fabrication'), ('Tailoring and Garments Design', 'Tailoring and Garments Design')], max_length=255)),
                ('programme_status', models.CharField(choices=[('Full Time Government (1 Year)', 'Full Time Government (1 Year)'), ('Full Time Private (1 Year)', 'Full Time Private (1 Year)')], max_length=50)),
                ('sponsor_name', models.CharField(max_length=255)),
                ('sponsor_address', models.CharField(max_length=255)),
                ('sponsor_phone', models.CharField(max_length=15)),
                ('sponsor_email', models.EmailField(max_length=254)),
                ('declaration_signature', models.CharField(blank=True, max_length=255, null=True)),
                ('endorser_name', models.CharField(blank=True, max_length=255, null=True)),
                ('endorser_designation', models.CharField(blank=True, max_length=255, null=True)),
                ('endorser_institution', models.CharField(blank=True, max_length=255, null=True)),
                ('endorser_address', models.CharField(blank=True, max_length=255, null=True)),
                ('endorser_signature', models.CharField(blank=True, max_length=255, null=True)),
                ('official_stamp', models.CharField(blank=True, max_length=255, null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='declarationendorsement',
            name='personal_info',
        ),
        migrations.DeleteModel(
            name='DITTEApplication',
        ),
        migrations.RemoveField(
            model_name='educationbackground',
            name='personal_info',
        ),
        migrations.RemoveField(
            model_name='employmentrecord',
            name='personal_info',
        ),
        migrations.RemoveField(
            model_name='sponsorship',
            name='personal_info',
        ),
        migrations.RemoveField(
            model_name='programme',
            name='personal_info',
        ),
        migrations.DeleteModel(
            name='DeclarationEndorsement',
        ),
        migrations.DeleteModel(
            name='EducationBackground',
        ),
        migrations.DeleteModel(
            name='EmploymentRecord',
        ),
        migrations.DeleteModel(
            name='Sponsorship',
        ),
        migrations.DeleteModel(
            name='PersonalInfo',
        ),
        migrations.DeleteModel(
            name='Programme',
        ),
    ]
