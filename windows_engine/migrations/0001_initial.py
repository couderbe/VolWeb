# Generated by Django 3.2.13 on 2022-06-12 14:04

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('investigations', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Timeliner',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Plugin', models.TextField(null=True)),
                ('Description', models.TextField(null=True)),
                ('AccessedDate', models.TextField(null=True)),
                ('ChangedDate', models.TextField(null=True)),
                ('CreatedDate', models.TextField(null=True)),
                ('ModifiedDate', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='TimeLineChart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('graph', models.JSONField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Strings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('String', models.TextField(null=True)),
                ('PhysicalAddress', models.BigIntegerField(null=True)),
                ('Result', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='SkeletonKeyCheck',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.BigIntegerField(null=True)),
                ('Process', models.TextField(null=True)),
                ('SkeletonKeyFound', models.TextField(null=True)),
                ('rc4HmacInitialize', models.TextField(null=True)),
                ('rc4HmacDecrypt', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='PsTree',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('graph', models.JSONField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='PsScan',
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
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='ProcessDump',
            fields=[
                ('process_dump_id', models.AutoField(primary_key=True, serialize=False)),
                ('pid', models.BigIntegerField()),
                ('filename', models.CharField(max_length=255)),
                ('case_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Privs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.BigIntegerField(null=True)),
                ('Process', models.TextField(null=True)),
                ('Value', models.BigIntegerField(null=True)),
                ('Privilege', models.TextField(null=True)),
                ('Attributes', models.TextField(null=True)),
                ('Description', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='NetStat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Offset', models.BigIntegerField(null=True)),
                ('Proto', models.TextField(null=True)),
                ('LocalAddr', models.TextField(null=True)),
                ('LocalPort', models.TextField(null=True)),
                ('ForeignAddr', models.TextField(null=True)),
                ('ForeignPort', models.TextField(null=True)),
                ('State', models.TextField(null=True)),
                ('PID', models.BigIntegerField(null=True)),
                ('Owner', models.TextField(null=True)),
                ('Created', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='NetScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Offset', models.BigIntegerField(null=True)),
                ('Proto', models.TextField(null=True)),
                ('LocalAddr', models.TextField(null=True)),
                ('LocalPort', models.TextField(null=True)),
                ('ForeignAddr', models.TextField(null=True)),
                ('ForeignPort', models.TextField(null=True)),
                ('State', models.TextField(null=True)),
                ('PID', models.BigIntegerField(null=True)),
                ('Owner', models.TextField(null=True)),
                ('Created', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='NetGraph',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('graph', models.JSONField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Malfind',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.BigIntegerField(null=True)),
                ('Process', models.TextField(null=True)),
                ('StartVPN', models.BigIntegerField(null=True)),
                ('EndVPN', models.BigIntegerField(null=True)),
                ('Tag', models.TextField(null=True)),
                ('Protection', models.TextField(null=True)),
                ('CommitCharge', models.BigIntegerField(null=True)),
                ('PrivateMemory', models.BigIntegerField(null=True)),
                ('Fileoutput', models.TextField(null=True)),
                ('Hexdump', models.TextField(null=True)),
                ('Disasm', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Lsadump',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Key', models.TextField(null=True)),
                ('Secret', models.TextField(null=True)),
                ('Hex', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='HiveList',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('FileFullPath', models.TextField(null=True)),
                ('Offset', models.BigIntegerField(null=True)),
                ('Fileoutput', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Hashdump',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('User', models.TextField(null=True)),
                ('rid', models.BigIntegerField(null=True)),
                ('lmhash', models.TextField(null=True)),
                ('nthash', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='FileScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Offset', models.BigIntegerField(null=True)),
                ('Name', models.TextField(null=True)),
                ('Size', models.BigIntegerField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='FileDump',
            fields=[
                ('file_dump_id', models.AutoField(primary_key=True, serialize=False)),
                ('offset', models.BigIntegerField(null=True)),
                ('filename', models.CharField(max_length=255)),
                ('case_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Envars',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.BigIntegerField(null=True)),
                ('Process', models.TextField(null=True)),
                ('Block', models.TextField(null=True)),
                ('Variable', models.TextField(null=True)),
                ('Value', models.TextField(null=True)),
                ('Description', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='CmdLine',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.BigIntegerField(null=True)),
                ('Process', models.TextField(null=True)),
                ('Args', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='Cachedump',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.TextField(null=True)),
                ('domain', models.TextField(null=True)),
                ('domain_name', models.TextField(null=True)),
                ('hash', models.TextField(null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='investigations.uploadinvestigation')),
            ],
        ),
    ]
