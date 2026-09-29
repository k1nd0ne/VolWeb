#!/bin/sh

set -e  # Ferma l'esecuzione in caso di errore

echo "=== STARTING ENTRYPOINT ==="

if [ "$DATABASE" = "postgresql" ] || [ "$DATABASE" = "postgres" ]; then
    echo "Waiting for postgres..."

    # Aspetta che PostgreSQL sia raggiungibile
    while ! nc -z $DATABASE_HOST $DATABASE_PORT; do
      echo "PostgreSQL is unavailable - sleeping"
      sleep 1
    done    

    echo "PostgreSQL is ready!"
fi

# Only one service runs migrations/static/admin; running them in every worker
# would make concurrent migrate runs race on the same DDL.
if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "=== STARTING MIGRATIONS ==="
    echo "Current working directory: $(pwd)"
    echo "Current user: $(whoami)"
    echo "Python version: $(python --version)"

    echo "Checking migration status..."
    if ! python manage.py showmigrations --list > /dev/null 2>&1; then
        echo "Migration table appears to be corrupted. Attempting to fix..."

        python manage.py migrate --run-syncdb --verbosity=2 || {
            echo "Syncdb failed, trying fake-initial migration..."
            python manage.py migrate --fake-initial --verbosity=2
        }
    else
        echo "Migration table exists, proceeding normally..."
        echo "Django apps: $(python manage.py showmigrations --list)"
    fi

    echo "Making migrations..."
    python manage.py makemigrations cases evidences yararulesets yararules volatility_engine symbols --noinput --verbosity=2

    echo "Applying migrations..."
    python manage.py migrate --noinput --verbosity=2

    echo "Migrations completed successfully!"

    echo "Collecting static files..."
    python manage.py collectstatic --noinput --verbosity=2

    echo "Creating admin user if not exists..."
    python manage.py initadmin
else
    echo "=== SKIPPING MIGRATIONS (RUN_MIGRATIONS not set) ==="
fi

echo "=== ENTRYPOINT COMPLETED ==="

exec "$@"