# Generated by Django 3.2.12 on 2022-06-29 12:01

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('investigations', '0001_initial'),
        ('windows_engine', '0002_auto_20220612_1409'),
    ]

    operations = [
        migrations.CreateModel(
            name='PsList',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.BigIntegerField(null=True)),
                ('PPID', models.BigIntegerField(null=True)),
                ('ImageFileName', models.CharField(max_length=255, null=True)),
                ('Offset', models.BigIntegerField(null=True)),
                ('Threads', models.BigIntegerField(null=True)),
                ('Handles', models.BigIntegerField(null=True)),
                ('SessionId', models.BigIntegerField(null=True)),
                ('Wow64', models.BooleanField()),
                ('CreateTime', models.CharField(max_length=255, null=True)),
                ('ExitTime', models.CharField(max_length=255, null=True)),
                ('Fileoutput', models.CharField(max_length=255, null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_pslist_investigation', to='investigations.uploadinvestigation')),
            ],
        ),
    ]
