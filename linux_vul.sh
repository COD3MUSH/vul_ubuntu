#!/bin/sh
#home/test_bash

#문자열검색 grep -n 'host' /etc/profile
# grep -n '.xp' /etc/profile
#두번째글자와세번째글자로'xp'를 포함

#특정 문자의 패턴 추출
#ls -l /sbin/ifconfig | awk '{print $1 $2}'

# n>&m : 표준출력과 표준에러를 서로바꾸는것
# 0,1,2는 각각 표준입력,표준출력,표준에러를 의미
# 2>&1은 표준출력의 전달되는곳으로 표준에러를 전달하라는 의미
# if -option
#[ -z ] : 문자열의 길이가 0이면 참
#[ -n ] : 문자열의 길이가 0이 아니면 참
#[ -eq ] : 값이 같으면 참
#[ -ne ] : 값이 다르면 참
#[ -gt ] :  값1 > 값2
#[ -ge ] : 값1  >= 값2
#[ -lt ] : 값1 < 값2
#[ -le ] : 값1 <= 값2

#[ -a ] : &&연산과 동일 and 연산
#[ -o ] : ||연산과 동일 xor 연산

#[ -d ] : 파일이 디렉토리면 참
#[ -e ] : 파일이 있으면 참
#[ -L ] : 파일이 심볼릭 링크면 참
#[ -r ] : 파일이 읽기 가능하면 참
#[ -s ] : 파일의 크기가 0 보다 크면 참
#[ -w ] : 파일이 쓰기 가능하면 참
#[ -x ] : 파일이 실행 가능하면 참
#[ 파일1 -nt 파일2 ]  : 파일1이 파일2보다 최신파일이면 참
#[ 파일1 -ot 파일2 ]  : 파일1이 파일2보다 이전파일이면 참
#[ 파일1 -ef 파일2 ] : 파일1이 파일2랑 같은 파일이면 참


CREATE_FILE="result_linux_vul".txt #결과 리포트
echo > $CREATE_FILE 2>&1
echo "========1-1.Default 계정 삭제========" >> $CREATE_FILE 2>&1 #2>&1은 오류 출력
echo " " >> $CREATE_FILE 2>&1
cat /etc/passwd | egrep "lp:|uucp:|nuucp:" | wc -l > vultemp
vulresult=$(cat vultemp)
if [ $vulresult = 0 ] #Safe
then
  echo '\033[31m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  echo "lp, uucp, nuucp not found" >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/passwd | egrep "lp:|uucp:|nuucp:" >> $CREATE_FILE 2>&1
fi

# 01.시스템에서 이용하지 않는 Default 계정 및 의심스러운 계정의 존재유무를 검사하여 삭제함.
# 패스워드 추측공격에 악용될 수 있음 (중)

echo " " >> $CREATE_FILE 2>&1
echo "========1-2.root 이외의 UID가 ‘0’ 금지========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
awk -F: '$3==0' /etc/passwd | wc -l > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  awk -F: '$3==0 { print $1 " => UID="$3}' /etc/passwd >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  awk -F: '$3==0 { print $1 " => UID="$3}' /etc/passwd >> $CREATE_FILE 2>&1
fi

# 02.root 권한을 가진 다른 일반 계정이 있는지 점검. root와 UID 가 중복되어있으면 관리자 권한을 다른 사용자가 사용할수 있으며,
# 사용자 간 UID 중복시 사용자 감사 추적이 어렵고, 사용자 권한이 중복됨.
# 일반계정의 UID가 '0'이면 삭제 또는 적절한 UID 부여(100이상의 번호) (상)

echo " " >> $CREATE_FILE 2>&1
echo "========1-3.패스워드 사용규칙 적용========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

# 패스워드 최소길이
cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | awk '{print $2}' > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -gt 7 ]
then
  echo "PASS_MIN_LEN Result : Safe" > password
  # 패스워드 최소길이가 7보다 크면 양호
else
  echo "PASS_MIN_LEN Result : UnSafe" > password
fi

# 패스워드 최소 사용기간

cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}' > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -gt 3 ]
then
  echo "PASS_MIN_DAYS Result : Safe" >> password
  # 패스워드 최소 사용기간이 0보다 크면 양호
else
  echo "PASS_MIN_DAYS Result : UnSafe" >> password
fi

# 패스워드 최대 사용기간
cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}' > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -gt 70 ]
then
  echo "PASS_MAX_DAYS Result : UnSafe" >> password
  # 패스워드 최대 사용기간이 70보단 크면 취약
else
  echo "PASS_MAX_DAYS : Safe" >> password
fi

# Result
cat password | grep -i "UnSafe" | wc -l > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -eq 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  grep -v "#" /etc/login.defs | grep -i "PASS_MIN_LEN" >> $CREATE_FILE 2>&1
  grep -v "#" /etc/login.defs | grep -i "PASS_MIN_DAYS" >> $CREATE_FILE 2>&1
  grep -v "#" /etc/login.defs | grep -i "PASS_MAX_DAYS" >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  grep -v "#" /etc/login.defs | grep -i "PASS_MIN_LEN" >> $CREATE_FILE 2>&1
  grep -v "#" /etc/login.defs | grep -i "PASS_MIN_DAYS" >> $CREATE_FILE 2>&1
  grep -v "#" /etc/login.defs | grep -i "PASS_MAX_DAYS" >> $CREATE_FILE 2>&1
fi
# rm -rf password
# password 임시파일삭제

# etc/login.defs파일에 PASS_MIN_LEN 5 를 추가해준상태
# 5. 패스워드 추측공격을 피하기위하여 최소길이가 설정되어있어야함

echo " " >> $CREATE_FILE 2>&1
echo "========1-4.root 계정 원격 접속 제한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

# pts가 존재하면 원격이 가능하므로 취약
cat /etc/securetty | grep ^pts | wc -l > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -eq 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  echo "^pts file not found" >> $CREATE_FILE
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/securetty | grep ^pts >> $CREATE_FILE 2>&1
fi
# 4.root는 시스템을 관리하는 중요한계정이므로,
# 원격 접속허용은 공격자에게 좋은 기회를 제공할 수 있으므로 원격 접속은 금지해야함

echo " " >> $CREATE_FILE 2>&1
echo "========1-5.계정 잠금 임계값 설정========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
cat /etc/pam.d/common-auth | grep -i "required" | awk '{print $4}' | grep "deny=5" | wc -l > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/pam.d/common-auth | grep -i "deny=" >> $CREATE_FILE 2>&1

else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/pam.d/common-auth | grep -i "required" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-1.Root 홈, 패스 디렉터리 권한 및 패스 설정========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo $PATH > path
cat path | grep "::" | wc -l > vultemp
vulresult=$(cat vultemp)
if [ $vulresult -eq 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  cat path >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat path >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-2.passwd 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/passwd | awk '{print $1}' | grep ".rw-r--r--" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/passwd | awk '{print $3}' | grep "root" | wc -l > uidtemp
uidresult=$(cat uidtemp)
if [ $vulresult -eq 1 ] && [ $uidresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/passwd >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/passwd >> $CREATE_FILE 2>&1
fi
# 2-2./etc/passwd 파일의접근권한을 제한하고있는지 점검
# 파일의 설정상의 문제점이나 파일 permission 등을 진단하여
# 관리자의 관리상 실수나 오류로 발생할 수 있는 침해사고의 위험성을 진단

echo " " >> $CREATE_FILE 2>&1
echo "========2-3.group 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/group | awk '{print $1}' | grep ".rw-r--r--" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/group | awk '{print $3}' | grep "root" | wc -l > uidtemp
uidresult=$(cat uidtemp)
if [ $vulresult -eq 1 ] && [ $uidresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/group >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/group >> $CREATE_FILE 2>&1
fi
# 2-3. Group 파일을 일반사용자가 접근하여 변조하게되면,
# 인가되지않은 사용자가 root 그룹으로 등록되어 root 권한 획득 가능.
# 일반사용자들의 쓰기 권한을 제한하여야함

echo " " >> $CREATE_FILE 2>&1
echo "========2-4.shadow 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/shadow | awk '{print $1}' | grep ".r--------" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/shadow | awk '{print $3}' | grep "root" |wc -l > uidtemp
uidresult=$(cat uidtemp)
if [ $vulresult -eq 1 ] && [ $uidresult ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/shadow >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/shadow >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-5.hosts 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/hosts | awk '{print $1}' | grep ".rw-------" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/hosts | awk '{print $3}' | grep "root" | wc -l > uidtemp
uidresult=$(cat uidtemp)
if [ $vulresult -eq 1 ] && [ $uidresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/hosts >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/hosts >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-6.(x)inetd.conf 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/xinetd.conf | awk '{print $1}' | grep ".r--------" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/xinetd.conf | awk '{print $3}' | grep "root" | wc -l > uidtemp
uidresult=$(cat uidtemp)
ls -al /etc/xinetd.conf | wc -l > nofiletemp
nofileresult=$(cat nofiletemp)
if [ $vulresult -eq 1 ] && [ $uidresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/xinetd.conf >> $CREATE_FILE 2>&1
elif [ $nofileresult -eq 0 ]
then
  echo '\033[33m'"Check Result :
There are no such files or directories"'\033[0m' >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/xinetd.conf >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-7.syslog.conf 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

ls -alL /etc/rsyslog.conf | awk '{print $1}' | grep ".rw-r--r--" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/rsyslog.conf | awk '{print $3}' | grep "root" | wc -l > uidtemp
uidresult=$(cat uidtemp)
ls -al /etc/rsyslog.conf | wc -l > nofiletemp
nofileresult=$(cat nofiletemp)

if [ $vulresult -eq 1 ] && [ $uidresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/rsyslog.conf >> $CREATE_FILE 2>&1
elif [ $nofileresult -eq 0 ]
then
  echo '\033[33m'"Check Result :
There are no such files or directories"'\033[0m' >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/rsyslog.conf >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-8./etc/services 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/services | awk '{print $1}' | grep ".rw-r--r--" | wc -l > vultemp
vulresult=$(cat vultemp)
ls -al /etc/services | awk '{print $3}' | grep "root" | wc -l > uidtemp
uidresult=$(cat uidtemp)

if [ $vulresult -eq 1 ] && [ $uidresult -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/services >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/services >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========2-9./dev device 파일 접근권한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
find /dev -type f -exec ls -l {} \; | grep "," | wc -l > vultemp
vulresult=$(cat vultemp)

if [ $vulresult -eq 0 ] # -ne : 값이 다르면 참
then
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  find /dev -type f -exec ls -l {} \; >> $CREATE_FILE 2>&1
else
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  find /dev -type f -exec ls -l {} \; | grep "," >> $CREATE_FILE 2>&1
fi
#find /dev -type f -exec ls -l {} \;
# Exec 옵션 뒤에 명령어를 입력하면 검색한 파일로 부가적인 작업을 수행 가능
# -exec 명령 {} \; / -type f(일반타입의 파일을 지정하여 검색)
# Ex : ( Major, minor number ) 12,0 (o)/ 978525 (x)



echo " " >> $CREATE_FILE 2>&1
echo "========2-10.UMASK 설정 관리========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
cat /etc/profile | awk '{print $1, $2 }' | grep "umask" | grep -v "export" | awk '{print $2}' > vultemp
vulresult=$(cat vultemp)

if [ $vulresult -le 022 ] # -le : 값이 같거나 작으면 참
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/profile | awk '{print $1, $2 }' | grep "umask" | grep -v "export" >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/profile | awk '{print $1, $2 }' | grep "umask" | grep -v "export" >> $CREATE_FILE 2>&1
fi

# 3. 서비스 관리

echo " " >> $CREATE_FILE 2>&1
echo "========3-1.Finger 서비스 비활성화========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#cat /etc/services | grep "finger" | wc -l > vultemp
# 포트 확인 가능

cat /etc/inetd.conf | awk '{print $q}' | grep "finger" | grep -v "#" | wc -l = vultemp
vulresult=$(cat vultemp)

ls -al /usr/bin/finger | wc -l > fingertemp
fingerresult=$(cat fingertemp)

# ls -al /usr/bin/finger -eq 1 unsafe

if [ $fingerresult -eq 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  echo "Do not install the program 'finger'." >> $CREATE_FILE
elif [ $vulresult -gt 0 ]
then
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/inetd.conf | awk '{print $q}' | grep "finger" | grep -v "#" >> $CREATE_FILE
  #
else
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
fi

# /etc/xinetd/finger 파일의 삭제
# /etc/services 파일내에서 finger 행의 삭제 또는 주석( # ) 처리



echo " " >> $CREATE_FILE 2>&1
echo "========3-2.Anonymous FTP 비활성화========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

cat /etc/passwd | grep "ftp" | wc -l > vultemp
vulresult=$(cat vultemp)

if [ $vulresult -eq 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1

else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/passwd | grep "ftp" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========3-3.r 계열 서비스 비활성화========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

cat /etc/services | awk '{print $1}' | egrep "rsh|rlogin|rexec" | wc -l > vultemp
vulresult=$(cat vultemp)

if [ $vulresult -eq 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1

else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/services | egrep "rsh|rlogin|rexec" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========3-4.cron 파일 소유자 및 권한설정========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

ls -l /etc/cron.d/cron.allow | wc -l > nofiletemp
ls -l /etc/cron.d/cron.deny | wc -l > nofiletemp1
nofileresult=$(cat nofiletemp)
nofileresult1=$(cat nofiletemp1)

ls -alL /etc/cron.d/cron.allow | awk '{print $1}' | grep ".rw-r-----" | wc -l > allowtemp
resultallow=$(cat allowtemp)

ls -alL /etc/cron.d/cron.deny | awk '{print $1}' | grep ".rw-r-----" | wc -l > denytemp
resultdeny=$(cat denytemp)

if [ $nofileresult -eq 0 ] && [ $nofileresult1 -eq 0 ]
then
  echo '\033[33m'"Check Result :
There are no such files or directories"'\033[0m' >> $CREATE_FILE 2>&1
elif [ $resultallow -eq 1 ] && [ $resultdeny -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/cron.d/cron.allow >> $CREATE_FILE 2>&1
  ls -alL /etc/cron.d/cron.deny >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ls -alL /etc/cron.d/cron.allow >> $CREATE_FILE 2>&1
  ls -alL /etc/cron.d/cron.deny >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========3-5.ssh 원격접속 허용========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

ps -ax | grep sshd | grep -v "grep" | wc -l > vultemp
vulresult=$(cat vultemp)

if [ $vulresult -gt 0 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  ps -ax | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1

else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ps -ax | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1

fi


echo " " >> $CREATE_FILE 2>&1
echo "========3-6.SNMP 서비스 구동 점검========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

ps -ef | grep snmp | grep -v "grep" | awk '{print $1}' | grep "snmp" | wc -l > vultemp
vulresult=$(cat vultemp)
#service --status-all | grep snmp

if [ $vulresult -gt 0 ]
then
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1
  ps -ef | egrep -v "grep|root" | grep "snmp" >> $CREATE_FILE 2>&1
else
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "========3-7.expn, vrfy 명령어 제한========" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

cat /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep "novrfy" | wc -l > cmpvalue1
resultcmpvalue1=$(cat cmpvalue1)
cat /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep "noexpn" | wc -l > cmpvalue2
resultcmpvalue2=$(cat cmpvalue2)

# -eq 0 unsafe
# || or

if [ $resultcmpvalue1 -eq 1 ] && [ $resultcmpvalue2 -eq 1 ]
then
  echo '\033[32m'"Check Result : Safe"'\033[0m' >> $CREATE_FILE 2>&1
  cat /etc/mail/sendmail.cf | grep "PrivacyOptions" | egrep "novrfy|noexpn" >> $CREATE_FILE 2>&1
else
  echo '\033[31m'"Check Result : UnSafe"'\033[0m' >> $CREATE_FILE 2>&1

fi





rm -f allowtemp
rm -f denytemp
rm -f nofiletemp
rm -f nofiletemp1
rm -f password
rm -f path
rm -f uidtemp
rm -f vultemp
rm -f cmpvalue1
rm -f cmpvalue2

# echo "test ======== aa"> test.html
# sed 's/========/********/' test.html


cat ./$CREATE_FILE
