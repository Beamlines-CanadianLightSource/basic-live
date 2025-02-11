# Generated by Django 4.0.6 on 2022-08-30 20:22

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('lims', '0097_session_proposal'),
    ]

    operations = [
        migrations.AddField(
            model_name='proposal',
            name='active',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='group',
            name='proposal',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sample_groups', to='lims.proposal', verbose_name='Project Number'),
        ),
        migrations.AlterField(
            model_name='sample',
            name='proposal',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='samples', to='lims.proposal', verbose_name='Project Number'),
        ),
    ]
