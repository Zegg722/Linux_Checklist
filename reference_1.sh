#!/bin/sh

function showTitle()
{
    echo "* $1"
    echo "=========================================================================================="
}

function showEndline()
{
    echo "------------------------------------------------------------------------------------------"
    echo
}

showTitle "2.1 계정 및 패스워드 관리 : 2.1.1 로그인 설정"
echo "=> 해당사항 없음"
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.2 root 이외의 UID가 0인 계정 존재여부"
echo "점검 : root 계정만 UID가 0이면 양호"
TARGET1=/etc/passwd
CHECK1=$(awk -F: '$3 == 0 {print $0}' $TARGET1)
CHECK2=$(printf '%s\n' $CHECK1 | wc -l)
if [[ -n $CHECK1 ]]; then
        if [[ 1 == $CHECK2 ]]; then
                echo -e "=> 양호\n- UID가 0인 계정\n$CHECK1"
        else
                echo -e "=> 취약\n- root 외 UID가 0인 계정 삭제 시 양호\n$CHECK1"
        fi
else
        echo -e "=> 점검 \nUID가 0인 계정 없음"
fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.3 불필요한 계정 존재 여부(Default)"
echo "점검 : /etc/passwd 파일에 lp, uucp, nuucp 등 불필요 계정이 모두 존재하지 않으면 양호"
TARGET1=/etc/passwd
CHECK1=$(awk -F: '{print $1}' $TARGET1 | egrep 'lp|uucp|nuucp')
if [[ -z $CHECK1 ]]; then
    echo -e "=> 양호 \nlp, uucp, nuucp 계정이 존재하지 않습니다."
else
    echo -e "=> 취약\n- 아래 불필요한 계정 삭제(userdel -r 계정명)\n$CHECK1"

fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.4 shell 제한"
echo "점검 : 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin) 셸이 부여되어 있으면 양호"
TARGET1=/etc/passwd
CHECK1=$(cat $TARGET1 | egrep -v '/bin/false|/sbin/nologin')
echo -e "=> 로그인 불필요 계정 셸 변경(usermod -s /bin/false 계정명)\n$CHECK1"
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.5 passwd 파일 권한 설정"
echo "점검 : 파일 퍼미션이 644 이하면 양호"
TARGET1=/etc/passwd
CHECK1=$(ls -al $TARGET1)
CHECK2=$(find $TARGET1 -perm 644 -o -perm 444 | wc -l)
if [[ 1 == $CHECK2 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 퍼미션 644 이하 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.6 group 파일 권한 설정"
echo "점검 : 파일 퍼미션이 644 이하면 양호"
TARGET1=/etc/group
CHECK1=$(ls -al $TARGET1)
CHECK2=$(find $TARGET1 -perm 644 -o -perm 444 | wc -l)
if [[ 1 == $CHECK2 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 퍼미션 644 이하 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.7 shadow 파일 권한 설정"
echo "점검 : 파일 퍼미션이 600 이하면 양호"
TARGET1=/etc/shadow
CHECK1=$(ls -al $TARGET1)
CHECK2=$(find $TARGET1 -perm 600 -o -perm 000 | wc -l)
if [[ 1 == $CHECK2 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 퍼미션 600 이하 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.8 패스워드의 최소 길이 제한 설정"
echo "점검 : 패스워드 정책 설정 시 양호"
TARGET1=/etc/login.defs
CHECK1=$(awk '$1 == "PASS_MIN_LEN" && $2 {print $0}' $TARGET1)
CHECK2=$(awk '$1 == "PASS_MIN_LEN" && $2 {print $2}' $TARGET1)
if [[ 8 -le $CHECK2 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 8자리 이상 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.9 패스워드의 최대 사용기간 설정"
TARGET1=/etc/login.defs
CHECK1=$(awk '$1 == "PASS_MAX_DAYS" && $2 {print $0}' $TARGET1)
CHECK2=$(awk '$1 == "PASS_MAX_DAYS" && $2 {print $2}' $TARGET1)
if [[ 95 -ge $CHECK2 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 95일 이하로 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.1 계정 및 패스워드 관리 : 2.1.10 취약한 패스워드 존재여부"
echo "점검 : 영문 대/소문자, 숫자, 특수문자 4종류 중 3종류 이상 조합하여 최소 10자리 이상 설정 시 양호"
echo -e "=> 양호"
showEndline

showTitle "2.2 접근제어 : 2.2.1 일반 사용자의 su 명령어 제한"
echo "점검 : /etc/pamd./su 파일 pam_wheel.so debug group=wheel 또는 pam_wheel.so use_uid 설정 시 양호"
TARGET1=/etc/pam.d/su
CHECK1=$(grep pam_wheel.so $TARGET1 | grep -v '#')
if [[ -n $CHECK1 ]]; then
        echo -e "=> 양호\n$CHECK1"
else
        echo -e "=> 취약\n- 아래 내용 추가 시 양호\nauth        required    pam_wheel.so use_uid"
fi
echo -e "\n"
echo "점검 : pam_rootok.so 설정 시 양호"
CHECK1=$(grep pam_rootok.so $TARGET1 | grep -v '#')
if [[ -n $CHECK1 ]]; then
        echo -e "=> 양호\n$CHECK1"
else
        echo -e "=> 취약\n- 아래 내용 추가 시 양호\nauth            sufficient      pam_rootok.so"
fi
showEndline

showTitle "2.2 접근제어 : 2.2.2 root 계정 Telnet 제한"
echo "점검 : /etc/pam.d/login 파일에 pam_securetty.so 설정 주석(#)이 없으면 양호"
TARGET1=/etc/pam.d/login
CHECK1=$(grep pam_securetty.so $TARGET1 | grep -v '#')
if [[ -n $CHECK1 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 아래 내용 추가 시 양호\nauth       required     pam_securetty.so"
fi
showEndline

showTitle "2.2 접근제어 : 2.2.3 root계정 ftp 접속 제한"
echo "점검 : ftp 서비스를 사용하지 않거나 ftpusers에 root 계정이 있으면 양호"
TARGET1=/etc/ftpusers
CHECK1=$(ps -ef | grep ftpd | grep -v pts)
if [[ -n $CHECK1 ]]; then
    CHECK2=$(grep -i root $TARGET1)
    if [[ -n $CHECK2 ]]; then
        echo -e "=> 양호\nftp 서비스 실행 상태\n$TARGET1 파일내 root 계정 확인"
    else
        echo -e "=> 취약\nftp 서비스 실행 상태\n$TARGET1 파일내 root 계정 추가 시 양호"
    fi
else
    echo -e "=> 양호\nftp 서비스 중지 상태"
fi
showEndline

showTitle "2.2 접근제어 : 2.2.4 익명 FTP 을 제한"
echo "점검 : ftp 서비스를 사용하지 않거나 ftp 계정이 없으면 양호"
TARGET1=/etc/passwd
CHECK1=$(ps -ef | grep ftpd | grep -v pts)
CHECK2=$(awk -F: '{print $1}' $TARGET1 | grep ftp)
if [[ -n $CHECK1 ]]; then
        if [[ -z $CHECK2 ]]; then
                echo -e "=> 양호\nftp 서비스 실행 상태\n$TARGET1 파일 ftp 계정 없음"
        else
                echo -e "=> 취약\nftp 서비스 실행 상태\n$TARGET1 파일 ftp 계정 삭제 시 양호"
        fi
else
        if [[ -z $CHECK2 ]]; then
                echo -e "=> 양호\nftp 서비스 중지 상태\n$TARGET1 파일 ftp 계정 없음"
        else
                echo -e "=> 취약\nftp 서비스 중지 상태\n$TARGET1 파일 ftp 계정 삭제 시 양호"
        fi
fi
showEndline

showTitle "2.2 접근제어 : 2.2.5 세션 타임아웃을 설정"
echo "점검: export TMOUT=300 설정 시 양호"
TARGET1=/etc/profile
if [[ -e $TARGET1 ]]; then
    CHECK1=$(grep 'TMOUT=300' $TARGET1 | grep -v '#')
    if [[ -n $CHECK1 ]]; then
        echo -e "=> 양호 \n$CHECK1 설정 확인"
    else
        echo -e "=> 취약 \n- 아래 내용 추가 시 양호\nexport TMOUT=300"
    fi
else
        echo -e "=> 취약 \n$TARGET1 파일 없음"
fi
showEndline

showTitle "2.2 접근제어 : 2.2.6 r-commands 제한"
echo "점검 : rsh, rlogin, rexec(shell login, exec) 서비스 비활성화 시 양호"
CHECK1=$(ps -ef | egrep -i 'rsh|rlogin|rexec|inetd|xinetd' | grep -v pts)
CHECK2=$(find /home -name .rhosts)
CHECK3=$(find /etc/ -name hosts.equiv)
if [[ -z $CHECK1 ]]; then
    if [[ -z $CHECK2 && -z $CHECK3 ]]; then
        echo -e "=> 양호 \nr-command 서비스 중지 상태, 접근 제어 파일 없음"
    else
        echo -e "=> 취약 \nr-commnad 서비스 중지 상태\n$CHECK2 $CHECK3 접근 제어 파일 삭제 시 양호"
    fi
else
    echo -e "=> 취약 \nr-command 서비스 실행 상태\n$CHECK1"
fi
showEndline

showTitle "2.2 접근제어 : 2.2.7 NFS 공유관련 취약점을 제거 여부"
TARGET1=/etc/exports
CHECK1=$(ps -ef | egrep 'nfsd|statd|mountd' | grep -v pts)
if [[ -z $CHECK1 ]]; then
        echo -e "=> 양호 \nnfs 서비스 중지 상태"
else
        echo -e "=> 점검 \nnfs 서비스 실행 상태\nnfs 미사용 서버일 경우 서비스 종료"
        cat $TARGET1
fi
showEndline

showTitle "2.3 시스템 보안 : 2.3.1 crontab 관련 파일에 대한 접근 제한"
echo "점검 : other 의 쓰기권한이 없으면 양호"
CHECK1=$(find /etc/cron.weekly /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/crontab -type f -perm -2)
if [[ -z $CHECK1 ]]; then
        echo -e "=> 양호 \nother 쓰기 권한 파일 없음"
else
        echo -e "=> 취약 \n$CHECK1 파일 other 쓰기 권한 있음"
fi
showEndline

showTitle "2.3 시스템 보안 : 2.3.2 PATH 환경 변수 설정"
echo "점검 : 현재 위치를 의미하는 . 이 없거나 PATH 맨 뒤에 존재하면 양호\nPATH 환경변수에 설정된 디렉터리에 타사용자 쓰기 권한이 없는 경우 양호"
CHECK1=$(/usr/bin/printenv | grep PATH | grep '\:\.\:')
if [[ -z $CHECK1 ]]; then
    echo -e "=> 양호 \npath 경로에 . 없음"
else
    echo -e "=> 취약 \npath 경로에 . 제거 시 양호"
fi
showEndline

showTitle "2.3 시스템 보안 : 2.3.3 UMASK 설정"
echo "점검 : umask 값이 022, 027 이면 양호"
CHECK1=$(egrep 'umask 022|umask 027' /etc/profile /etc/bashrc | wc -l)
if [[ 2 -eq $CHECK1 ]]; then
    echo -e "=> 양호 \n/etc/profile, /etc/bashrc 파일에 umask 022 설정 확인"
else
    echo -e "=> 취약 \n/etc/profile, /etc/bashrc 파일에 umask 022 설정 시 양호"
fi
showEndline

showTitle "2.3 시스템 보안 : 2.3.4 hosts 파일의 권한 설정"
echo "점검 : /etc/hosts 파일 권한 중 other 의 쓰기권한이 없으면 양호"
CHECK1=$(find /etc/hosts -perm -2)

if [[ -z $CHECK1 ]]; then
        echo -e "=> 양호 \nother 쓰기 권한 없음"
else
        echo -e "=> 취약 \nother 쓰기 권한 제거 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.3 시스템 보안 : 2.3.5 xinetd.conf 파일의 권한 설정"
echo "점검 : xinetd 파일 other 의 쓰기권한이 없으면 양호"
CHECK1=$(find /etc/xinetd* -type f -perm -2)
if [[ -z $CHECK1 ]]; then
        echo -e "=> 양호 \nother 쓰기 권한 없음"
else
        echo -e "=> 취약 \nother 쓰기 권한 제거 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.3 시스템 보안 : 2.3.6 hosts.equiv 파일의 권한 설정"
echo "점검 : hosts.equiv 파일이 없거나 퍼미션이 400이면 양호"
TARGET1=/etc/hosts.equiv
CHECK1=$(find /etc/ -name hosts.equiv -perm 400)
if [[ -e $TARGET1 ]]; then
        if [[ -n $CHECK1 ]]; then
                echo -e "=> 양호 \n$TARGET1 파일 확인 및 퍼미션 400 확인"
        else
                echo -e "=> 취약 \n$TARGET1 파일 확인 및 퍼미션 400 설정 시 양호"
        fi
else
        echo -e "=> 양호 \n/etc/hosts.equiv 파일 없음"
fi
showEndline

showTitle "2.4 서비스 보안 : 2.4.1 서비스 파일 권한 설정"
echo "점검 : /etc/service 파일 other 의 쓰기권한이 없으면 양호"
TARGET1=/etc/services
CHECK1=$(find /etc/ -name services -perm -2)
if [[ -e $TARGET1 ]]; then
        if [[ -z $CHECK1 ]]; then
                echo -e "=> 양호 \n$TARGET1 파일 other 쓰기 권한 없음"
        else
                echo -e "=> 취약 \n$TARGET1 파일 other 쓰기 권한 제거 시 양호"
        fi
else
        echo -e "- 점검 \n$TARGET1 파일 없음"
fi
showEndline

showTitle "2.4 서비스 보안 : 2.4.2 기타 서비스 설정"
echo "점검 : /etc/xinetd.d/ 미사용 서비스 설정이 disable = yes 일시 양호"
CHECK1=$(grep -irF 'disable' /etc/xinetd.d/ | grep no)
if [[ -z $CHECK1 ]]; then
        echo -e "=> 양호 \nxinetd 서비스 disable=no 설정 없음"
else
        echo -e "=> 취약 \n- xinetd 서비스 disable = yes 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.4 서비스 보안 : 2.4.3 서비스 Banner 관리"
echo "점검 : Telnet, FTP 가 구동 중이지 않거나 배너에 OS 및 버전 정보가 없을 경우 양호"
CHECK1=$(find /etc/ -name issue -o -name proftpd.conf -o -name vsftpd.conf -o -name main.cf -o -name named.conf | xargs egrep -i 'release|message|version|banner' | grep -v '#')
if [[ -z $CHECK1 ]]; then
        echo -e "=> 양호 \nmessage, version, banner 비공개 설정"
else
        echo -e "=> 취약 \n- message, version, banner 비공개 설정 시 양호\n$CHECK1"
fi
showEndline

showTitle "2.4 서비스 보안 : 2.4.4 SNMP 서비스 설정"
echo "점검 : Community String이 public, private 이 아니면 양호"
TARGET1=/etc/snmp/snmpd.conf
CHECK1=$(ps -ef | grep snmp | grep -v pts)
if [[ -n $CHECK1 ]]; then
        CHECK2=$(egrep 'public|private' $TARGET1 | grep -v '#' | grep -v pts)
        if [[ -e $TARGET1 ]]; then
                if [[ -z $CHECK2 ]];then
                        echo -e "=> 양호 \nsnmpd 서비스 실행 상태\npublic, private community 없음"
                else
                        echo -e "=> 취약 \nsnmpd 서비스 실행 상태\npublic, private community 제거 시 양호"
                fi
        else
                echo -e "=> 점검 \nsnmpd 서비스 실행 상태\n/etc/snmp/snmpd.conf 파일 없음"
        fi
else
        echo -e "=> 양호 \nsnmpd 서비스 중지 상태"
fi
showEndline

showTitle "2.5 로그관리 및 보안패치 : 2.5.1 syslog 기록 설정"
echo "점검 : syslog 로그 설정이 되어 있는 경우 양호"
TARGET1=/etc/rsyslog.conf
CHECK1=$(ps -ef | grep rsyslog | grep -v pts)
if [[ -n $CHECK1 ]]; then
        CHECK2=$(grep -v '#' /etc/rsyslog.conf | egrep 'info|authpriv|maillog|cron|alert|emerg' | wc -l)
        if [[ 6 -eq $CHECK2 ]]; then
                echo -e "=> 양호 \nrsyslog 서비스 실행 상태\n6개 로그 설정 확인"
        else
                echo -e "=> 취약 \nrsyslog 서비스 실행 상태\n- 아래 로그 설정 시 양호\n\n- CentOS 6\n*.info;mail.none;authpriv.none;cron.none                /var/log/messages\n\
authpriv.*                                              /var/log/secure\nmail.*                                                  -/var/log/maillog\n\
cron.*                                                  /var/log/cron\n*.alert                                                  /var/log/messages\n\
*.emerg                                                 *\n\n- CentOS 8\n*.info;mail.none;authpriv.none;cron.none                /var/log/messages\n\
authpriv.*                                              /var/log/secure\nmail.*                                                  -/var/log/maillog\n\
cron.*                                                  /var/log/cron\n*.alert                                                  /var/log/messages\n\
*.emerg                                                 :omusrmsg:*"
        fi
else
        echo -e "=> 취약 \nrsyslog 중지 상태"
fi
showEndline

showTitle "2.5 로그관리 및 보안패치 : 2.5.2 su 로그를 기록 설정"
echo "점검 : sulog 설정이 되어 있는 경우 양호"
echo -e "=> 양호\n/var/log/secure 파일에 기록"
#TARGET1=/etc/login.defs
#TARGET2=/etc/rsyslog.conf
#CHECK1=$(grep sulog $TARGET1 | grep -v '#')
#CHECK2=$(grep sulog $TARGET2 | grep -v '#')
#if [[ -n $CHECK1 && -n $CHECK2 ]]; then
#    echo -e "=> 양호 \nsulog 로그 설정 확인"
#else
#    echo -e "=> 취약 \n- 아래 설정 추가 시 양호\n/etc/login.defs : SULOG_FILE /var/log/sulog\n/etc/rsyslog.conf : auth.info                                               /var/log/sulog"
#fi
showEndline

showTitle "2.5 로그관리 및 보안패치 : 2.5.3 보안 패치"
echo "점검 : 주기적으로 서버의 최신 보안패치를 하고 있고, 필수 보안 패치 항목이 패치 된 경우 양호"
echo -e "=> 취약\n취약점 패치 및 업데이트 미진행"
showEndline
