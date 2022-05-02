# Generated by Django 3.2.5 on 2022-01-28 18:43

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Activity',
            fields=[
                ('date', models.DateField(primary_key=True, serialize=False)),
                ('count', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='UploadInvestigation',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255)),
                ('os_version', models.CharField(choices=[('Windows', 'Windows')], max_length=50)),
                ('investigators', models.CharField(max_length=255)),
                ('description', models.TextField(max_length=255)),
                ('status', models.CharField(max_length=20)),
                ('taskid', models.CharField(max_length=255)),
                ('existingPath', models.CharField(max_length=255, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('eof', models.BooleanField()),
                ('uid', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='ProcessDump',
            fields=[
                ('process_dump_id', models.AutoField(primary_key=True, serialize=False)),
                ('pid', models.IntegerField()),
                ('filename', models.CharField(max_length=255)),
                ('case_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
                ('is_malicious', models.BooleanField(default=False)),
                ('threat',models.CharField(max_length=255,default="")),
            ],
        ),
        migrations.CreateModel(
            name='FileDump',
            fields=[
                ('file_dump_id', models.AutoField(primary_key=True, serialize=False)),
                ('offset', models.IntegerField()),
                ('filename', models.CharField(max_length=255)),
                ('case_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
    ]
