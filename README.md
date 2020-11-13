## 주요정보통신기반시설 기술적 취약점 분석, 평가 방법 상세 가이드 
### 과학기술정보통신부, KISA 한국인터넷진흥원 (2017.12)

Script by Zegg

--------------------------------
## HOW TO USE
```sh
$ chmod 700 linux_checklist.sh
$ ./linux_checklilst.sh > security_check.log
$ cat security_check.log
```

--------------------------------
## UNIX SERVER
### 1. 계정 관리
| code | checklist |
| ------ | ------ |
| U-01 | root 계정 원격 접속 제한 |
| U-02 | 패스워드 복잡성 설정 |
| U-03 | 계정 잠금 임계값 설정 |
| U-04 | 패스워드 파일 보호 |
| U-44 | root 이외의 UID가 '0' 금지 |
| U-45 | root 계정 su 제한 |
| U-46 | 패스워드 최소 길이 설정 |
| U-47 | 패스워드 최대 사용기간 설정 |
| U-48 | 패스워드 최소 사용 기간 설정 |
| U-49 | 불필요한 계정 제거 |
| U-50 | 관리자 그룹에 최소한의 계정 포함 |
| U-51 | 계정이 존재하지 않는 GID 금지 |
| U-52 | 동일한 UID 금지 |
| U-53 | 사용자 shell 점검 |
| U-54 | Session Timeout 설정 |
 
### 2. 파일 및 디렉토리 관리
| code | checklist |
| ------ | ------ |
| U-05 | root 홈, 패스 디렉터리 권한 및 패스 설정 |
| U-06 | 파일 및 디렉토리 소유자 설정 |
| U-07 | /etc/passwd 파일 소유자 및 권한 설정 |
| U-08 | /etc/shadow 파일 소유자 및 권한 설정 |
| U-09 | /etc/hosts 파일 소유자 및 권한 설정 |
| U-10 | /etc/(x)inetd.conf 파일 소유자 및 권한 설정 |
| U-11 | /etc/syslog.conf 파일 소유자 및 권한 설정 |
| U-12 | /etc/services 파일 소유자 및 권한 설정 |
| U-13 | SUID, SGID, Sticky bit 설정 파일 점검 |
| U-14 | 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 |
| U-15 | world writable 파일 점검 |
| U-16 | /dev에 존재하지 않는 device 파일 점검 |
| U-17 | $HOME/.rhosts, hosts.equiv 사용 금지 |
| U-18 | 접속 IP 및 포트 제한 |
| U-55 | hosts.lpd 파일 소유자 및 권한 설정 |
| U-56 | NIS 서비스 비활성화 |
| U-57 | UMASK 설정 관리 |
| U-58 | 홈디렉토리 소유자 및 권한 설정 |
| U-59 | 홈디렉토리로 지정한 디렉토리의 존재 관리 |
| U-60 | 숨겨진 파일 및 디렉토리 검색 및 제거 |

### 3. 서비스 관리
| code | checklist |
| ------ | ------ |
| U-19 | finger 서비스 비활성화 |
| U-20 | Anonymous FTP 비활성화 |
| U-21 | r 계열 서비스 비활성화 |
| U-22 | cron 파일 소유자 및 권한설정 |
| U-23 | Dos 공격에 취약한 서비스 비활성화 |
| U-24 | NFS 서비스 비활성화 |
| U-25 | NFS 접근 통제 |
| U-26 | automountd 제거 |
| U-27 | RPC 서비스 확인 |
| U-28 | NIS, NIS+ 점검 |
| U-29 | tftp, talk 서비스 비활성화 |
| U-30 | Sendmail 버전 점검 |
| U-31 | 스팸 메일 릴레이 제한 |
| U-32 | 일반사용자의 Sendmail 실행 방지 |
| U-33 | DNS 보안 버전 패치 |
| U-34 | DNS Zone Transfer 설정 |
| U-35 | Apache 디렉토리 리스팅 제거 |
| U-36 | Apache 웹 프로세스 권한 제한 | 
| U-37 | Apache 상위 디렉토리 접근 금지 |
| U-38 | Apache 불필요한 파일 제거 |
| U-39 | Apache 링크 사용 금지 |
| U-40 | Apache 파일 업로드 및 다운로드 제한 |
| U-41 | Apache 웹 서비스 영역의 분리 |
| U-61 | ssh 원격접속 허용 |
| U-62 | ftp 서비스 확인 |
| U-63 | ftp 계정 shell 제한 |
| U-64 | Ftpusers 파일 소유자 및 권한 설정 |
| U-65 | Ftpusers 파일 설정 |
| U-66 | at 파일 소유자 및 권한 설정 |
| U-67 | SNMP 서비스 구동 점검 |
| U-68 | SNMP 서비스 커뮤니티스트링의 복잡성 설정 |
| U-69 | 로그온 시 경고 메시지 제공 |
| U-70 | NFS 설정파일 접근 제한 |
| U-71 | expn, vrfy 명령어 제한 |
| U-72 | Apache 웹 서비스 정보 숨김 |

### 4. 패치 관리
| code | checklist |
| ------ | ------ |
| U-42 | 최신 보안패치 및 벤더 권고사항 적용 |

### 5. 로그 관리
| code | checklist |
| ------ | ------ |
| U-43 | 로그의 정기적 검토 및 보고 |
| U-73 | 정책에 따른 시스템 로깅 설정 |
