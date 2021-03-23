from python:3.8-slim

COPY requirements.txt /app/

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y dumb-init && \
    rm -rf /var/lib/apt/lists/* && \
    pip install -r /app/requirements.txt

COPY app /app/
WORKDIR /app

ENTRYPOINT ["/usr/bin/dumb-init", "/usr/local/bin/python", "/app/run.py"]
