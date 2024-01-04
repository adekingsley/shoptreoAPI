web: gunicorn treo.wsgi
release: python manage.py makemigrations --noinput
release: python manage.py collectstatics --noinput
release: python manage.py migrate --noinput