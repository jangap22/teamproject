FROM python:3.11-slim

# 시스템 패키지 업데이트 및 필수 도구 설치
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# PEP 668 무시하고 scapy 설치 (--break-system-packages 옵션 사용)
RUN pip3 install --no-cache-dir --break-system-packages scapy

WORKDIR /app
COPY attack.py .
COPY attack3.py .

# 로우 소켓 사용을 위해 실행 권한 부여
RUN chmod +x attack.py
RUN chmod +x attack3.py

CMD ["python3", "attack.py"]