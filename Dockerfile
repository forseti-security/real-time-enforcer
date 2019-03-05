from python:slim

COPY requirements.txt /app/

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y dumb-init && \
    rm -rf /var/lib/apt/lists/* && \
    pip install -r /app/requirements.txt

COPY *.py /app/

ENTRYPOINT ["/usr/bin/dumb-init", "/usr/local/bin/python", "/app/run.py"]
