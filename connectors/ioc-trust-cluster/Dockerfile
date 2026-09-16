FROM python:3.12-slim

WORKDIR /opt/opencti-connector-ioc-trust-cluster

# Install dependencies first (layer-cached separately from source)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector source
COPY src/ src/

RUN adduser --disabled-password --no-create-home connector
USER connector

ENTRYPOINT ["python", "src/connector.py"]
