from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('The username field must be set')
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(username, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    USER_ROLES = [
        ('user', 'User'),
        ('merchant', 'Merchant'),
        ('admin', 'Admin')
    ]

    role = models.CharField(max_length=20, choices=USER_ROLES, default='user')
    date_joined = models.DateTimeField(default=timezone.now, null=True)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True, null=True)
    first_name = models.CharField(max_length=30, null=True)
    last_name = models.CharField(max_length=30, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['role', 'first_name', 'last_name']

    def __str__(self):
        return f"{self.username} - {self.get_role_display()}"


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class ProductCategory(models.TextChoices):
    GENERAL = 'general', 'General'
    FOOD = 'food', 'Food'
    UTILITIES = 'utilities', 'Utilities'
    FURNITURE = 'furniture', 'Furniture'
    TOYS = 'toys', 'Toys'
    VEHICLES = 'vehicles', 'Vehicles'
    GADGETS = 'gadgets', 'Gadgets'
    HOUSES = 'houses', 'Houses'


class Product(TimeStampedModel):
    category = models.CharField(max_length=20, choices=ProductCategory.choices)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField()
    image = models.ImageField(upload_to='product_images/')

    def __str__(self):
        return self.name


class Order(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    products = models.ManyToManyField(Product, through='OrderItem')
    total_price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"Order #{self.id} - {self.user.username}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.quantity} x {self.product.name} in Order #{self.order.id}"
