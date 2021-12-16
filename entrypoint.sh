#!/bin/sh

if [ "$DATABASE" = "postgres" ]; then
    echo "Waiting for postgres..."

    while ! nc -z $DATABASE_HOST $DATABASE_PORT; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi

# Make migrations and migrate the database.
echo "Making migrations and migrating the database. "
python manage.py makemigrations --noinput
python manage.py migrate --noinput --run-syncdb
python manage.py collectstatic --noinput
python manage.py initadmin
#echo "from django.contrib.auth.models import User; user = User(username = 'admin', email = 'admin@volweb.com', first_name = 'Admin', last_name = 'Account'); user.set_password('password'); user.is_superuser = True; user.is_staff = True; user.save()" | python3 manage.py shell
exec "$@"
