# Generated by Django 3.2.12 on 2022-07-12 14:30

import analyser.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analyser', '0002_auto_20220712_1618'),
    ]

    operations = [
        migrations.AlterField(
            model_name='rule',
            name='file',
            field=models.FileField(storage=analyser.models.RulesStorage(), upload_to='analyser/rules'),
        ),
    ]
