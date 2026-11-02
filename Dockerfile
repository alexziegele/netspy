FROM python:3.12-alpine

RUN apk add --no-cache iputils tzdata

WORKDIR /app
COPY app/ /app/

ENV DB_PATH=/data/netwatch.db \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Berlin

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s CMD wget -qO- http://127.0.0.1:${WEB_PORT:-8080}/health || exit 1

CMD ["python", "/app/netwatch.py"]
