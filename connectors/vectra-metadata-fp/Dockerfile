FROM python:3.12-slim

WORKDIR /opt/opencti-connector-vectra-metadata-fp

RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY scripts/ scripts/

RUN adduser --disabled-password --no-create-home --gecos "" connector
USER connector

WORKDIR /opt/opencti-connector-vectra-metadata-fp/src
ENTRYPOINT ["python", "connector.py"]
