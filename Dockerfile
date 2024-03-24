FROM python:3.10

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_HOME=/home/app/web \
    PATH="/home/app/.local/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends netcat-traditional \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --user-group --create-home --no-log-init --shell /bin/bash app

RUN mkdir -p $APP_HOME/staticfiles \
 && chown -R app:app $APP_HOME

COPY --chown=app:app . $APP_HOME
USER app
WORKDIR $APP_HOME

RUN pip install --upgrade pip \
 && pip install --user -r requirements.txt

ENTRYPOINT ["./entrypoint.sh"]
