# Generated by Django 4.0.6 on 2022-08-25 16:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lims', '0094_requesttype_scope'),
    ]

    operations = [
        migrations.AlterField(
            model_name='requesttype',
            name='edit_template',
            field=models.CharField(default='requests/base-edit.html', max_length=100),
        ),
    ]
