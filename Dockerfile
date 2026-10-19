# Guarded browser-agent service — deployable image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTGUARD_MODEL=gpt-4.1-mini

WORKDIR /app
COPY . /app

# Install the guard + service deps, then the matching Chromium and its OS libs.
RUN pip install ".[serve]" \
    && python -m playwright install --with-deps chromium

# The image ships the signed default policy + public key (policies/).
# The private signing key is NOT in the image.
EXPOSE 8080
CMD ["uvicorn", "deploy.service:app", "--host", "0.0.0.0", "--port", "8080"]
