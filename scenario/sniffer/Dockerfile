FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# 시스템 패키지 업데이트 및 패킷 캡처/분석 도구 설치
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    net-tools \
    iputils-ping \
    iproute2 \
    dnsutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Python 패킷 분석용 라이브러리 설치
RUN pip3 install --no-cache-dir --break-system-packages \
    scapy \
    pandas \
    scikit-learn \
    joblib

WORKDIR /sniffer

COPY . .

RUN chmod +x main.py

CMD ["python3", "main.py"]
