# Generated by Django 3.0.6 on 2020-07-21 15:28

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields


class Migration(migrations.Migration):

    dependencies = [
        ('crm', '0062_supportarea_user_feedback'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserFeedback',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name='created')),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name='modified')),
                ('comments', models.TextField(blank=True, null=True, verbose_name='Provide comments to explain or give context to the ratings you selected')),
                ('project', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'db_table': 'lims_userfeedback',
            },
        ),
        migrations.CreateModel(
            name='UserAreaFeedback',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rating', models.IntegerField(choices=[(1, 'Impressed'), (2, 'Satisfied'), (3, 'Needs Improvement'), (4, 'Needs Urgent Attention'), (5, 'N/A')], default=5)),
                ('area', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='crm.SupportArea')),
                ('feedback', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='crm.UserFeedback')),
            ],
            options={
                'db_table': 'lims_userareafeedback',
            }
        ),
    ]

    replaces = [
        ('lims', '0063_userareafeedback_userfeedback'),
    ]