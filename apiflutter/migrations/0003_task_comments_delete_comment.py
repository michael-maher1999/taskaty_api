# Generated by Django 4.2.4 on 2024-07-31 07:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apiflutter', '0002_comment'),
    ]

    operations = [
        migrations.AddField(
            model_name='task',
            name='comments',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.DeleteModel(
            name='Comment',
        ),
    ]
