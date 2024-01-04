from gettext import translation
from django.forms import ValidationError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, ListAPIView, UpdateAPIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import redirect
from django.http import HttpResponse
from .models import CustomUser, Order, OrderItem, Product, ProductCategory
from .serializers import CustomUserSerializer, LoginSerializer, LogoutSerializer, OrderItemSerializer, OrderSerializer, ProductSerializer, ProductSerializer
from .token import AccountActivationTokenGenerator
from rest_framework.permissions import BasePermission
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.parsers import MultiPartParser, FormParser
from django.db import transaction
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.core.cache import cache
from collections import OrderedDict


class AllowAny(BasePermission):
    def has_permission(self, request, view):
        return True


class UserRegistrationView(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = CustomUserSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = CustomUserSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            self.validate_user_data(serializer.validated_data)

            user = self.perform_create(serializer)

            activation_token = AccountActivationTokenGenerator().make_token(user)
            self.send_activation_email(request, user, activation_token)

            return Response({'message': 'User registered successfully. Please check your email for activation.'}, status=status.HTTP_201_CREATED)

        except ValidationError as ve:
            error_messages = []
            if hasattr(ve, 'error_list'):
                for error in ve.error_list:
                    error_messages.append(str(error))
            else:
                error_messages.append(str(ve))
            return Response({'error': error_messages}, status=status.HTTP_400_BAD_REQUEST)

    def validate_user_data(self, validated_data):
        self.validate_user_exists(validated_data)
        self.validate_password(validated_data['password'])
        self.validate_username(validated_data['username'])
        self.validate_names(validated_data['first_name'])
        self.validate_names(validated_data['last_name'])

    def validate_user_exists(self, serializer):
        if isinstance(serializer, OrderedDict):
            email = serializer.get('email')
        else:
            email = serializer.validated_data.get('email')

        try:
            existing_user = CustomUser.objects.filter(email=email).exists()
            if existing_user:
                raise ValidationError(
                    {'email': 'User with this email already exists.'})
        except ObjectDoesNotExist:
            pass

    def validate_password(self, password):
        try:
            validate_password(password)
        except ValidationError as e:
            raise ValidationError({'password': e.messages})

    def validate_username(self, username):
        if len(username) < 3:
            raise ValidationError(
                {'error': 'Username must be more than three characters'})

        for i in username:
            if not (i.isalpha() or i.isdigit()):
                raise ValidationError(
                    {'error': 'Username cannot contain non-alphabetic and non-numeric characters'})

    def validate_names(self, name):
        if len(name) < 3:
            raise ValidationError(
                {'error': 'Name must be more than three characters'})

        for i in name:
            if not i.isalpha():
                raise ValidationError(
                    {'error': 'Firstname or Lastname must contain alphabets only'})

    def send_activation_email(self, request, user, token):
        current_site = get_current_site(request)
        mail_subject = 'Activate your account'
        message = render_to_string('acc_active_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': token,
        })

        to_email = user.email
        email = EmailMessage(mail_subject, message, to=[to_email])
        email.send()

    def perform_create(self, serializer):
        user = serializer.save()
        user.is_active = False
        user.save()
        return user


SignUP = UserRegistrationView.as_view()


def activate_account(request, uidb64, token):
    User = CustomUser
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and AccountActivationTokenGenerator().check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Thank you for your email confirmation. Now you can log in to your account.')
    else:
        return HttpResponse('Activation link is invalid!')


class LoginView(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        if user is not None:
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                return Response(
                    {'access_token': access_token,
                     'refresh_token': refresh_token},
                    status=status.HTTP_200_OK
                )
            else:
                raise ValidationError("Please verify your email address.")
        else:
            return Response({'message': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)


Login = LoginView.as_view()


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    @method_decorator(cache_page(60 * 15))
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data['access_token']

        if cache.get(access_token):
            return Response({'detail': 'Token has already been blacklisted'}, status=status.HTTP_400_BAD_REQUEST)

        cache.set(access_token, True)

        request.auth.delete()

        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


Logout = LogoutView.as_view()


class ProductCreateView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = ProductSerializer(data=request.data)

        if serializer.is_valid():
            category_id = serializer.validated_data.get('category')

            try:
                ProductCategory.objects.get(id=category_id)
            except ProductCategory.DoesNotExist:
                return Response({'error': 'Invalid category ID.'}, status=status.HTTP_400_BAD_REQUEST)
            serializer.validated_data['owner'] = self.request.user
            serializer.save()

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductListByMerchantView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'merchant':
            return Response({'error': 'Unauthorized. Only merchants can access this endpoint.'}, status=status.HTTP_401_UNAUTHORIZED)

        products = Product.objects.filter(owner=request.user)
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProductDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        if request.user.role != 'merchant':
            return Response({'error': 'Unauthorized. Only merchants can delete products.'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            product = Product.objects.get(pk=pk)
            if product.owner != request.user:
                return Response({'error': 'Unauthorized. This product does not belong to the authenticated merchant.'}, status=status.HTTP_401_UNAUTHORIZED)
            product.delete()

            return Response({'message': 'Product deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except Product.DoesNotExist:
            return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)


class ProductUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def put(self, request, pk):
        if request.user.role != 'merchant':
            return Response({'error': 'Unauthorized. Only merchants can update products.'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            product = Product.objects.get(pk=pk)
            if product.owner != request.user:
                return Response({'error': 'Unauthorized. This product does not belong to the authenticated merchant.'}, status=status.HTTP_401_UNAUTHORIZED)
            serializer = ProductSerializer(
                product, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Product.DoesNotExist:
            return Response({'error': 'Product not found.'}, status=status.HTTP_404_NOT_FOUND)


class ProductListView(APIView):
    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ProductCategoryFilterView(APIView):
    def get(self, request, category_name):
        try:
            category = ProductCategory(category_name)
            products = Product.objects.filter(category=category)
            serializer = ProductSerializer(products, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ValueError:
            return Response({'error': 'Invalid category name.'}, status=status.HTTP_400_BAD_REQUEST)


class OrderMutilpleItemCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user = request.user
        order_data = {'user': user.id, 'total_price': 0}
        order_serializer = OrderSerializer(data=order_data)

        if order_serializer.is_valid():
            order = order_serializer.save()

            # Process each item in the request and add it to the order
            for item_data in request.data:
                item_data['order'] = order.id
                item_serializer = OrderItemSerializer(data=item_data)

                if item_serializer.is_valid():
                    item_serializer.save()
                    # Update the order's total_price based on the added item
                    order.total_price += item_data['quantity'] * \
                        item_data['product']['price']
                    order.save()
                else:
                    order.delete()
                    return Response(item_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({'message': 'Order created successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response(order_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderItemCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user = request.user
        open_order = Order.objects.filter(
            user=user, is_completed=False).first()
        if not open_order:
            order_data = {'user': user.id, 'total_price': 0}
            order_serializer = OrderSerializer(data=order_data)

            if order_serializer.is_valid():
                open_order = order_serializer.save()
            else:
                return Response(order_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        item_serializer = OrderItemSerializer(data=request.data)
        if item_serializer.is_valid():
            item_serializer.save(order=open_order)
            open_order.total_price += request.data['quantity'] * \
                request.data['product']['price']
            open_order.save()

            return Response({'message': 'Item added to order successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response(item_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderItemListView(ListAPIView):
    queryset = OrderItem.objects.all()
    serializer_class = OrderItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return OrderItem.objects.filter(order__user=user)


class OrderItemUpdateView(UpdateAPIView):
    queryset = OrderItem.objects.all()
    serializer_class = OrderItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        if user.is_authenticated:
            return OrderItem.objects.filter(order__user=user)
        else:
            return OrderItem.objects.none()
