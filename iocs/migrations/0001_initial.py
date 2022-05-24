# Generated by Django 3.2.5 on 2022-05-19 11:17

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('investigations', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='IOC',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('context', models.CharField(max_length=255)),
                ('value', models.CharField(max_length=255)),
                ('linkedInvestigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
    ]
