# Stoptreo API Documentation

Welcome to the Stoptreo API documentation. Stoptreo is a platform that provides various features for managing user accounts, products, and orders. Below are the available endpoints along with their descriptions.

## User Authentication

### 1. Sign Up

- **Endpoint**: `/api/signup`
- **Method**: `POST`
- **Description**: Create a new user account.
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "your_password"
  }
  ```
- **Response**: Returns user details upon successful registration.

### 2. Login

- **Endpoint**: `/api/login`
- **Method**: `POST`
- **Description**: Authenticate and obtain an access token.
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "your_password"
  }
  ```
- **Response**: Returns an access token for authentication.

### 3. Logout

- **Endpoint**: `/api/logout`
- **Method**: `POST`
- **Description**: Log out the user and invalidate the access token.
- **Request Body**:
  ```json
  {
    "access_token": "your_access_token"
  }
  ```
- **Response**: Indicates successful logout.

### 4. Activate Account

- **Endpoint**: `/api/activate/<uidb64>/<token>/`
- **Method**: `GET`
- **Description**: Activate a user account using the activation link sent via email.

## Token Management

### 5. Obtain Token

- **Endpoint**: `/api/token/`
- **Method**: `POST`
- **Description**: Obtain a new access token.
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "your_password"
  }
  ```
- **Response**: Returns a new access token.

### 6. Refresh Token

- **Endpoint**: `/api/token/refresh/`
- **Method**: `POST`
- **Description**: Refresh an expired access token.
- **Request Body**:
  ```json
  {
    "refresh": "your_refresh_token"
  }
  ```
- **Response**: Returns a new access token.

### 7. Verify Token

- **Endpoint**: `/api/token/verify/`
- **Method**: `POST`
- **Description**: Verify the validity of an access token.
- **Request Body**:
  ```json
  {
    "token": "your_access_token"
  }
  ```
- **Response**: Indicates whether the token is valid.

## Product Management

### 8. Create Product

- **Endpoint**: `/api/products/create/`
- **Method**: `POST`
- **Description**: Create a new product.
- **Request Body**: Provide product details.
- **Authentication**: Requires a valid access token.

### 9. List Products by Merchant

- **Endpoint**: `/api/products/list/`
- **Method**: `GET`
- **Description**: Retrieve a list of products owned by the authenticated merchant.
- **Authentication**: Requires a valid access token.

### 10. Delete Product

- **Endpoint**: `/api/products/delete/<int:pk>/`
- **Method**: `DELETE`
- **Description**: Delete a specific product by its ID.
- **Authentication**: Requires a valid access token.

### 11. Update Product

- **Endpoint**: `/api/products/update/<int:pk>/`
- **Method**: `PUT`
- **Description**: Update details of a specific product by its ID.
- **Request Body**: Provide updated product details.
- **Authentication**: Requires a valid access token.

### 12. List All Products

- **Endpoint**: `/api/products/list/all/`
- **Method**: `GET`
- **Description**: Retrieve a list of all products.
- **Authentication**: Requires a valid access token.

### 13. Filter Products by Category

- **Endpoint**: `/api/products/filter/<str:category_name>/`
- **Method**: `GET`
- **Description**: Filter products by a specific category.
- **Authentication**: Requires a valid access token.

## Order Management

### 14. Create Order Item

- **Endpoint**: `/api/order-item/create/`
- **Method**: `POST`
- **Description**: Create a new order item.
- **Request Body**: Provide order item details.
- **Authentication**: Requires a valid access token.

### 15. Create Multiple Order Items

- **Endpoint**: `/api/order-multiple-item/create/`
- **Method**: `POST`
- **Description**: Create multiple order items in a single request.
- **Request Body**: Provide details for multiple order items.
- **Authentication**: Requires a valid access token.

### 16. List Order Items

- **Endpoint**: `/api/order-items/`
- **Method**: `GET`
- **Description**: Retrieve a list of order items.
- **Authentication**: Requires a valid access token.

### 17. Update Order Item

- **Endpoint**: `/api/order-items/<int:pk>/`
- **Method**: `PUT`
- **Description**: Update details of a specific order item by its ID.
- **Request Body**: Provide updated order item details.
- **Authentication**: Requires a valid access token.

---

Please Note: its my first time of using swagger ui and it really mess up my codes 
will continue to update this code regardless 
