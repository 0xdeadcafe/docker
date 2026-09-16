FROM python:3.12-slim

WORKDIR /opt/opencti-connector-vectra-metadata-fp

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

RUN adduser --disabled-password --no-create-home connector
USER connector

WORKDIR /opt/opencti-connector-vectra-metadata-fp/src
ENTRYPOINT ["python", "connector.py"]
