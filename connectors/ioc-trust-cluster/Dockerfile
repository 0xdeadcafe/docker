FROM python:3.12-slim

WORKDIR /opt/opencti-connector-ioc-trust-cluster

RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (layer-cached separately from source)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector source
COPY src/ src/

RUN adduser --disabled-password --no-create-home connector
USER connector

ENTRYPOINT ["python", "src/connector.py"]
