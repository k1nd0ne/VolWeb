# Stage 1: Install dependencies
FROM python:3.10 AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/app/.local/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --user-group --create-home --no-log-init --shell /bin/bash app
USER app

WORKDIR /home/app/web
ENV PATH="/home/app/.local/bin:$PATH"

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Copy only the necessary parts from builder
FROM python:3.10

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/app/.local/bin:$PATH" \
    APP_HOME=/home/app/web

RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --user-group --create-home --no-log-init --shell /bin/bash app \
    && mkdir -p $APP_HOME/staticfiles \
    && chown -R app:app $APP_HOME

USER app
WORKDIR $APP_HOME
ENV PATH="/home/app/.local/bin:$PATH"

COPY --chown=app:app --from=builder /home/app/.local /home/app/.local
COPY --chown=app:app . $APP_HOME

ENTRYPOINT ["./entrypoint.sh"]
