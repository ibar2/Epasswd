# Generated by Django 4.2.3 on 2023-07-26 13:36

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("epasswd_app", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="hashers",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("userpk", models.IntegerField()),
                ("key", models.BinaryField()),
            ],
        ),
        migrations.CreateModel(
            name="partialpass",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("partof", models.IntegerField()),
                ("partial", models.BinaryField()),
                ("owner", models.IntegerField(default=None)),
            ],
        ),
        migrations.CreateModel(
            name="passwords",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("owner", models.IntegerField()),
                ("name", models.CharField(max_length=55, unique=True)),
                ("passwd", models.BinaryField()),
                ("tag", models.BinaryField()),
                ("nonce", models.BinaryField()),
                ("created_at", models.DateField(auto_now=True)),
            ],
        ),
    ]
