# Generated by Django 3.1.4 on 2020-12-10 21:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lims', '0082_auto_20201209_1049'),
    ]

    operations = [
        migrations.CreateModel(
            name='RequestType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('description', models.TextField(blank=True)),
                ('spec', models.JSONField()),
            ],
        ),
    ]
