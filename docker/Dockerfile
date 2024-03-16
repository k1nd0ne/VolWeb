# Use the official Python image from the Docker Hub
FROM python:3.10

# These two environment variables prevent __pycache__/ files.
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
# Create an app user in the app group.
RUN apt update && apt install netcat-traditional -y && useradd --user-group --create-home --no-log-init --shell /bin/sh app

ENV APP_HOME=/home/app/web
ENV PATH="/home/app/.local/bin:$PATH"

# Create the staticfiles directory. This avoids permission errors.
RUN mkdir -p $APP_HOME/staticfiles

# Change the workdir.
COPY . $APP_HOME
RUN chown -R app:app $APP_HOME; chmod +x $APP_HOME/entrypoint.sh
USER app
WORKDIR $APP_HOME
RUN pip install --upgrade pip && pip install --user -r requirements.txt
ENTRYPOINT ["/home/app/web/entrypoint.sh"]
