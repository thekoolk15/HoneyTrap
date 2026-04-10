FROM python:3.11-slim

LABEL maintainer="thekoolk15"
LABEL description="HoneyTrap - Multi-port intrusion detection honeypot"
LABEL version="1.0"

WORKDIR /app

COPY *.py .

RUN mkdir -p logs && \
    useradd -r -s /bin/false honeytrap && \
    chown -R honeytrap:honeytrap /app

USER honeytrap

EXPOSE 2222 8022 2022

CMD ["python", "honeytrap.py"]