FROM opencti/connector-abuseipdb:latest
COPY patch.py /tmp/patch.py
RUN python /tmp/patch.py && rm /tmp/patch.py
