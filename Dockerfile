FROM python:3.12-slim

# Run as an unprivileged user: the monitor only needs to *read* logs.
RUN useradd --create-home --uid 10001 logsentry
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY logsentry/ logsentry/
COPY dashboard/ dashboard/
RUN mkdir -p /data && chown logsentry /data

USER logsentry
ENV LOGSENTRY_HOST=0.0.0.0 \
    LOGSENTRY_PORT=8080 \
    LOGSENTRY_DB=/data/logsentry.db \
    PYTHONUNBUFFERED=1

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=2)"

# Default: watch the log files listed in LOGSENTRY_LOGS (comma-separated).
CMD ["python", "-m", "logsentry", "run"]
