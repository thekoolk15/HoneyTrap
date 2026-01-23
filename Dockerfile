FROM python:3.11-slim

LABEL maintainer="thekoolk15"
LABEL description="HoneyTrap - Multi-port intrusion detection honeypot"
LABEL version="1.0"

WORKDIR /app

COPY honeytrap.py .
COPY honeytrap_with_creds.py .
COPY config.py .
COPY analyzer.py .

RUN mkdir -p logs

EXPOSE 2222 8022 2022

CMD ["python", "honeytrap.py"]