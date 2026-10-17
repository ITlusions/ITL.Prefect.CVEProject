FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/opt/prefect \
    PREFECT_API_URL=http://prefect-server.prefect-demo.svc.cluster.local:4200/api

COPY requirements.txt /opt/prefect/requirements.txt
RUN pip install --no-cache-dir -r /opt/prefect/requirements.txt

COPY ./cvelist /opt/prefect/cvelist/
COPY prefect.yaml /opt/prefect/prefect.yaml

WORKDIR /opt/prefect
CMD ["prefect", "deploy", "--all"]
