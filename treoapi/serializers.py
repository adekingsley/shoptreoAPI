from django.conf import settings
from django.forms import ValidationError
from rest_framework import serializers
from .models import CustomUser, ProductCategory, Product, Order, OrderItem
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from rest_framework_simplejwt.views import TokenObtainPairView

# class CustomTokenObtainPairView(TokenObtainPairView):
#     serializer_class = YourCustomTokenSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['roles'] = user.role

        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data['roles'] = self.user.role
        return data


class CustomUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password',
                  'role', 'first_name', 'last_name']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        return data

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data['role'],
            username=validated_data['username'],
            first_name=validated_data["first_name"],
            last_name=validated_data['last_name']
        )
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})


class ProductCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductCategory
        fields = ['id', 'name']


class ProductSerializer(serializers.ModelSerializer):
    owner = CustomUserSerializer(read_only=True)

    class Meta:
        model = Product
        fields = ['id', 'category', 'owner', 'name',
                  'description', 'price', 'stock', 'image']
        read_only_fields = ('image_URL',)

    def create(self, validated_data):
        user = self.context['request'].user
        validated_data['user'] = user
        image_file = validated_data.pop('image', None)

        product = Product.objects.create(**validated_data)

        if image_file:
            file_path = f'media/{image_file.name}'
            product.image = image_file
            product.save()

            s3_url = settings.MEDIA_URL + file_path
            product.image_URL = s3_url
            product.save()

        return product


class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = OrderItem
        fields = ['id', 'order', 'product', 'quantity']


class OrderSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer()
    products = OrderItemSerializer(many=True)

    class Meta:
        model = Order
        fields = ['id', 'user', 'products', 'total_price']


class LogoutSerializer(serializers.Serializer):
    access_token = serializers.CharField()
