from django.urls import path
from . import views

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

urlpatterns = [
    path('signup', views.SignUP, name='signup'),
    path('login', views.Login, name='login'),
    path('logout', views.Logout, name='logout'),
    path(
        'activate/(?P<uidb64>[0-9A-Za-z_]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',
        views.activate_account,
        name='activate'
    ),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('products/create/', views.ProductCreateView.as_view(),
         name='create-product'),
    path('products/list/', views.ProductListByMerchantView.as_view(),
         name='list-products-by-merchant'),
    path('products/delete/<int:pk>/',
         views.ProductDeleteView.as_view(), name='delete-product'),
    path('products/update/<int:pk>/',
         views.ProductUpdateView.as_view(), name='update-product'),
    path('products/list/all/', views.ProductListView.as_view(),
         name='list-all-products'),
    path('products/filter/<str:category_name>/',
         views.ProductCategoryFilterView.as_view(), name='filter-products-by-category'),
    path('order-item/create/', views.OrderItemCreateView.as_view(),
         name='order-item-create'),
    path('order-multiple-item/create/', views.OrderMutilpleItemCreateView.as_view(),
         name='order-multiple-item-create'),
    path('order-items/', views.OrderItemListView.as_view(), name='order-item-list'),
    path('order-items/<int:pk>/', views.OrderItemUpdateView.as_view(),
         name='order-item-update'),
]
