ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG CIDR_FILTER_CONNECTOR
COPY patch.py quota_guard.py /tmp/
RUN CIDR_FILTER_CONNECTOR=${CIDR_FILTER_CONNECTOR} python /tmp/patch.py \
    && rm /tmp/patch.py /tmp/quota_guard.py
