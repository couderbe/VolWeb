# Generated by Django 3.2.12 on 2022-06-29 11:27

from django.db import migrations
from django.core.files.base import File
import os
import yaml

def import_rules(apps, schema_editor):
    Rule = apps.get_model('analyser', 'Rule')
    for root, dirs, files in os.walk("analyser/rules/"):
        for filename in files:
            path = os.path.join(root, filename)
            with  open(path, 'r') as f:
                data = yaml.load(f, Loader=yaml.SafeLoader)
                #TODO change os when adding linux
                Rule.objects.create(title=data['title'],os="Windows",file=File(f))
            os.remove(path)

class Migration(migrations.Migration):

    dependencies = [
        ('analyser', '0001_initial')
    ]

    operations = [
        migrations.RunPython(import_rules),
    ]
