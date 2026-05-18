FROM python:3.11-slim

# 시스템 패키지 업데이트 및 필수 도구 설치
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# DNS 질의 생성용 Python 라이브러리 설치
RUN pip3 install --no-cache-dir --break-system-packages dnspython

WORKDIR /client

COPY query_generator.py .

# 실행 권한 부여
RUN chmod +x query_generator.py

CMD ["python3", "query_generator.py"]