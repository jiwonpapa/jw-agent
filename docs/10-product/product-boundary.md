# Product Boundary

Status: Accepted  
Authority: Product  
Owner: Product Maintainer  
Last reviewed: 2026-07-21

## 목적

JW Agent는 Ubuntu 서버에서 발견된 서비스의 상태를 이해하기 쉽게 보여주고, 지원되는 정형 작업만 계획·검증·복구하는 **범용 서비스 설정·유지보수 제품**입니다.

범용은 “root로 아무 명령이나 실행”이 아니라, Nginx·systemd·PHP-FPM·DB·Redis 같은 서로 다른 서비스를 같은 안전 수명주기로 다룬다는 뜻입니다. 별도의 비-root OpenSSH terminal·SFTP는 자동화가 처리하지 못하는 수동 진단 경로이며 G1으로 분리합니다.

## 핵심 가치

- 무엇이 문제인지 한 화면에서 확인
- 변경 전 대상·영향·검증·원복 계획 확인
- 실패와 강제 종료 뒤 상태를 재구성
- 서버 한 대는 중앙관제 없이 독립 관리
- Linux 계정으로 공개 HTTPS·모바일·태블릿에서 관리
- 공개 경로 장애 시 SSH 터널로 복구
- 지원하지 않는 환경을 명확히 거부

## 대상 사용자

- VPS를 직접 운영하지만 전문 시스템 관리자는 아닌 개발자
- 1~20대 서버를 관리하는 프리랜서·웹에이전시
- 웹사이트·커뮤니티·쇼핑몰 운영자
- 소규모 MSP

## 제품이 아닌 것

- Webmin 대체 범용 패널
- 클라우드 VM 생성·과금·DNS 통합 플랫폼
- 재해복구 백업 제품
- SIEM·EDR·불변 원장 서비스
- root shell·범용 root file manager·무제한 브라우저 IDE
- AI 자동 운영자
