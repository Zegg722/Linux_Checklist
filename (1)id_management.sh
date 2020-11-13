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

##################### U-01 #####################
:<<'END'

$ cat /etc/pam.d/login
auth required /lib/security/pam_securetty.so ← 앞에 주석 있을 경우 삭제 
$ cat /etc/securetty
pts/0 ~ pts/x ← 관련 설정이 존재할 경우 삭제

/etc/pam.d/login: 슈퍼유저로 로그인할 수 있는 사용자 인증과 관련된 파일이다.
pam_securetty.so 모듈이 지정해놓은 보안 규칙을 만족해야만 로그인이 허용
이 모듈은 /etc/securetty 파일에서 지정되어있는 tty에서 요청한 슈퍼유저만 로그인을 허용한다.

pts(pseudo-terminal, 가상터미널) : Telnet, SSh 터미널 등을 이용하여 접속함
tty(terminal-teletype) : 서버와 연결된 모니터, 키보드 등을 통해 사용자가 콘솔로 직접 로그인함

END
#------------------- script -------------------

showTitle "U-01. 1.계정관리 > 1.1 root 계정 원격 접속 제한"
echo "시스템 정책에 root 계정의 원격 접속 차단 설정이 적용되어있는지 점검"
showEndline

echo "점검 : /etc/pam.d/login 파일에 pam_securetty.so 설정 주석(#)이 없으면 양호"
TARGET1=/etc/pam.d/login
CHECK1=$(grep pam_securetty.so $TARGET1 | grep -v '#')
if [[ -n $CHECK1 ]]; then
    echo -e "=> 양호\n$CHECK1"
else
    echo -e "=> 취약\n- 아래 내용 추가 시 양호\nauth required /lib/security/pam_securetty.so"
fi

echo " 점검 : /etc/securetty 파일 내 *pts/x 관련 설정이 존재하는지 점검"
TARGET1=/etc/securetty
CHECK1=$(grep *pts/* $TARGET1)
if [[ -n $CHECK1 ]]; then
    echo -e "=> 취약\n- pts/x 관련 설정 제거 필요"
else
    echo -e "=> 양호\n$CHECK1"
fi

showEndline
###############################################
