# Generated by Django 4.2.7 on 2024-04-13 05:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('bimsapp', '0003_form'),
    ]

    operations = [
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=120)),
                ('file', models.FileField(upload_to='upload/')),
                ('date', models.DateField()),
                ('is_verified', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Upload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=120)),
                ('tesseract_output', models.TextField()),
                ('date', models.DateField()),
            ],
        ),
    ]
