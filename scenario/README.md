# 테스트 방법


---

# 🛡️ Project: CVE-2025-40778 BIND9 Cache Poisoning Laboratory

이 프로젝트는 **BIND9 ** 리졸버에서 발생하는 **DNS Cache Poisoning ** 취약점(**CVE-2025-40778 **)을 재현하고, 이를 통해 발생할 수 있는 피싱 공격 시나리오를 시각적으로 증명하는 보안 실습 환경입니다.

---

## 🏗️ 1. 시스템 아키텍처 (Architecture)

모든 환경은 **Docker ** 컨테이너로 격리되어 있으며, 하나의 브리지 네트워크(`172.20.0.0/24`)로 연결됩니다.

| 노드 명칭 | 역할 | 할당 IP | 호스트 포트 | 기술 스택 |
| :---  | :--- | :--- | :--- | :--- |
| **Resolver** | 취약한 DNS 리졸버 (Victim) | `172.20.0.10` | `10053/udp` | BIND 9.18.x |
| **Auth Server** | 정상 권한 DNS 서버 (Mock) | `172.20.0.20` | `20053/udp` | BIND 9.x |
| **Attacker** | 패킷 주입 공격자 | `172.20.0.30` | - | Python 3.11, Scapy |
| **Real Web** | 정상 서비스 서버 (Green) | `172.20.0.50` | `8081/tcp` | Nginx (Alpine) |
| **Fake Web** | 위조 피싱 서버 (Red) | `172.20.0.60` | `8082/tcp` | Nginx (Alpine) |

---

## 📂 2. 디렉토리 구조 (Directory Structure)

```text
scenario/
├── docker-compose.yml        # 전체 서비스 네트워크 및 컨테이너 정의
├── resolver/                   # [Victim] 취약한 BIND9 리졸버
 │           ├── Dockerfile
 │           └── named.conf              # 리졸버 전용 설정 파일
├── auth/                       # [Mock] 가짜 권한 DNS 서버
 │           ├── Dockerfile
 │           ├── named.conf              # 권한 서버 설정
 │           └── bank.test.zone          # 도메인 레코드 정보
├── real-web/                   # [Normal] 정상 웹 서버
 │           ├── Dockerfile
 │           └── index.html              # 정상 사이트 페이지 (Green)
├── fake-web/                   # [Phishing] 위조 웹 서버 (공격자 서버)
 │           ├── Dockerfile
 │           └── index.html              # 피싱 사이트 페이지 (Red)
└── attacker/                   # [Attacker] Scapy 공격 스크립트
 |            ├── Dockerfile
 |            └── attack.py     # Cache Poisoning 공격 코드
```

---

## 🚦 3. 단계별 재현 가이드 (Step-by-Step)

### **Step 1: Resolver 구축**
* **목표**: 취약한 설정의 리졸버 기동.
* **검증**: `dig @localhost -p 10053 google.com` 결과 확인.

### **Step 2: DNS 체인 완성**
* **목표**: 리졸버가 `bank.test` 질의를 `auth` 서버로 포워딩하도록 설정.
* **검증**: `dig @localhost -p 10053 bank.test` 가 `172.20.0.50` (Real)을 반환하는지 확인.

### **Step 3: Cache Poisoning 실행**
* **목표**: $Transaction \ ID$ 예측 또는 추가 정보 구역 오염을 통한 캐시 변조.
* **검증**: `rndc dumpdb -cache` 명령어로 캐시 내 IP가 `172.20.0.60` (Fake)으로 바뀌었는지 확인.

### **Step 4: 통합 피싱 시나리오 테스트**
* **목표**: 클라이언트 관점에서 웹 접속 결과 변화 확인.
* **검증**: `curl` 요청 시 Green 페이지에서 Red 페이지로 전환되는지 확인.

---

## ⚠️ 4. 주요 주의 사항 (Critical Success Factors)

1.  **Race Condition 제어**: 도커 내부 통신은 매우 빠릅니다. 공격 성공률을 높이기 위해 `auth` 서버의 응답에 의도적인 지연($Latency$ )을 추가하는 것이 핵심입니다.
2.  **보안 옵션 비활성화**: 재현을 위해 리졸버의 `dnssec-validation` 을 반드시 `no` 로 설정해야 합니다.
3.  **권한 설정**: `attacker` 컨테이너는 로우 소켓 패킷 제작을 위해 `CAP_NET_RAW` 및 `CAP_NET_ADMIN` 권한이 부여된 상태로 실행되어야 합니다.
4. 사용자가 지시하기 전에는 절대 다음 step을 개발하지 말것
5. 실제 네트워크 환경에서 테스트 할때는, 반드시 사용자에게 권한을 요청할것

---

> **Note**: 본 프로젝트는 교육 및 보안 연구 목적으로 제작되었습니다. 승인되지 않은 시스템에 대한 공격 시도는 엄격히 금지됩니다.

---