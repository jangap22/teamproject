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
    numpy

WORKDIR /sniffer

COPY sniffer.py .

# 실행 권한 부여
RUN chmod +x sniffer.py

CMD ["python3", "sniffer.py"]
