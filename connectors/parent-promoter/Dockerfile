FROM python:3.12-slim

WORKDIR /opt/opencti-connector-parent-promoter

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

RUN adduser --disabled-password --no-create-home connector
USER connector

ENTRYPOINT ["python", "src/connector.py"]
