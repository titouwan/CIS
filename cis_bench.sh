#!/bin/bash

# https://github.com/titouwan/CIS

VERB=0
score=0

function inv {
	if [ $1 -ge 1 ]
	then
		echo "0"
	else
		echo "1"
	fi
}

function out {
	if [ -z $1 ]
	then
		echo "Cannot go further"
                exit 99
	else
		if [ $1 -eq 0 ]
		then
			RESULT="OK"
		else
			RESULT="NOK"
			let score=$score+1
		fi

		if [ "x$2" == "x" ]
		then
			NUM="0.0.0"
			TIT="Something"
		else
			shift
			NUM=$1
			shift
			TIT=$@
		fi 
	fi

	if [ "$RESULT" == "NOK" ] || [ "$VERB" == 1 ]
	then
		printf "%-10.9s %-90.89s %-10.9s \n" "$NUM" "$TIT" "$RESULT"
	fi
}

case $1 in
	"-v")	VERB=1
		;;
esac

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]
then
	echo "This script must be run as root" 1>&2
	exit 1
fi

# Make sure that we are on RHEL6 OS
if [ ! -f /etc/redhat-release ]
then
	echo "This script must be run on RHEL"
	exit 2
else
	grep Santiago /etc/redhat-release > /dev/null
	if [ $? -ne 0 ]
	then
		echo "This script must be run on version 6 of RHEL"
		exit 2
	fi
fi

### 1 - Install Updates, Patches and Additional Security Software ###
echo "### 1 - Install Updates, Patches and Additional Security Software"

## 1.1 - Filesystem Configuration ##

INT='1.1.1 Verify that there is a /tmp file partition in the /etc/fstab file'
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab > /dev/null
out $? $INT

INT='1.1.2 Set nodev option for /tmp Partition'
grep /tmp /etc/fstab | grep nodev > /dev/null
out $? $INT

INT='1.1.3 Set nosuid option for /tmp Partition' 
grep /tmp /etc/fstab | grep nosuid > /dev/null
out $? $INT

INT='1.1.4 Set noexec option for /tmp Partition'
grep /tmp /etc/fstab | grep noexec > /dev/null
out $? $INT

INT='1.1.5 Verify that there is a /var file partition in the /etc/fstab file'
grep "[[:space:]]/var[[:space:]]" /etc/fstab > /dev/null
out $? $INT

INT='1.1.6 Bind Mount the /var/tmp directory to /tmp'
#grep -e "^/tmp" /etc/fstab | grep /var/tmp > /dev/null
#grep -e "^/tmp" /etc/fstab | grep /var/tmp
grep "/tmp[[:space:]]*/var/tmp[[:space:]]*none[[:space:]]*bind" /etc/fstab > /dev/null
out $? $INT

INT='1.1.7 Create Separate Partition for /var/log'
grep /var/log /etc/fstab > /dev/null
out $? $INT

INT='1.1.8 Create Separate Partition for /var/log/audit' 
grep /var/log/audit /etc/fstab > /dev/null
out $? $INT

INT='1.1.9 Create Separate Partition for /home'
grep /home /etc/fstab > /dev/null
out $? $INT

INT='1.1.10 Add nodev Option to /home'
grep /home /etc/fstab | grep nodev > /dev/null
out $? $INT

INT='1.1.11 Add nodev Option to Removable Media Partitions' 
err=0
for i in `grep -v -e "^#" -e mapper -e /var* -e /boot -e proc -e sysfs -e devpts -e tmpfs -e "^$" /etc/fstab |awk '{print $1}'`
do 
	grep $i /etc/fstab|grep nodev > /dev/null
	let err=$err+$?
done
out $err $INT

INT='1.1.12 Add noexec Option to Removable Media Partitions'
err=0
for i in `grep -v -e "^#" -e mapper -e /var* -e /boot -e proc -e sysfs -e devpts -e tmpfs -e "^$" /etc/fstab |awk '{print $1}'`
do
        grep $i /etc/fstab|grep noexec > /dev/null
        let err=$err+$?
done
out $err $INT

INT='1.1.13 Add nosuid Option to Removable Media Partitions'
err=0
for i in `grep -v -e "^#" -e mapper -e /var* -e /boot -e proc -e sysfs -e devpts -e tmpfs -e "^$" /etc/fstab |awk '{print $1}'`
do
        grep $i /etc/fstab|grep nosuid > /dev/null
        let err=$err+$?
done
out $err $INT

INT='1.1.14 Add nodev Option to /dev/shm Partition'
grep /dev/shm /etc/fstab | grep nodev > /dev/null
out $? $INT

INT='1.1.15 Add nosuid Option to /dev/shm Partition'
grep /dev/shm /etc/fstab | grep nosuid > /dev/null
out $? $INT

INT='1.1.16 Add noexec Option to /dev/shm Partition'
grep /dev/shm /etc/fstab | grep noexec > /dev/null
out $? $INT

INT='1.1.17 Set Sticky Bit on All World-Writable Directories'
lin=`df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) |wc -l 2>/dev/null`
out $? $INT

INT='1.1.18 Disable Mounting of cramfs Filesystems'
/sbin/lsmod | grep cramfs > /dev/null
out $(inv $?) $INT

INT='1.1.19 Disable Mounting of freevxfs Filesystems'
/sbin/lsmod | grep freexvfs > /dev/null
out $(inv $?) $INT

INT='1.1.20 Disable Mounting of jffs2 Filesystems'
/sbin/lsmod | grep jffs2 > /dev/null
out $(inv $?) $INT

INT='1.1.21 Disable Mounting of hfs Filesystems' 
/sbin/lsmod | grep hfs > /dev/null
out $(inv $?) $INT

INT='1.1.22 Disable Mounting of hfsplus Filesystems'  
/sbin/lsmod | grep hfsplus > /dev/null
out $(inv $?) $INT

INT='1.1.23 Disable Mounting of squashfs Filesystems'
/sbin/lsmod | grep squashfs > /dev/null
out $(inv $?) $INT

INT='1.1.24 Disable Mounting of udf Filesystems'
/sbin/lsmod | grep udf > /dev/null
out $(inv $?) $INT

INT='1.1.25 Verify that there is a /opt file partition in the /etc/fstab file'
grep "[[:space:]]/opt[[:space:]]" /etc/fstab > /dev/null
out $? $INT

INT='1.1.26 Set nodev option for /opt Partition'
grep /opt /etc/fstab | grep nodev > /dev/null
out $? $INT

INT='1.1.27 Set nosuid option for /opt Partition'
grep /opt /etc/fstab | grep nosuid > /dev/null
out $? $INT

## 1.2 - Configure Software Updates ##
#echo "    1.2 - Configure Software Updates"

INT='1.2.1 Configure Connection to the RHN RPM Repositories'
/usr/bin/yum check-update|grep "not registered" > /dev/null
out $(inv $?) $INT

INT='1.2.2 Verify Red Hat GPG Key is Installed'
/bin/rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey  > /dev/null
out $? $INT

INT='1.2.3 Verify that gpgcheck is Globally Activated'
x=0
y=0
for i in /etc/yum.conf /etc/yum.repos.d/*
do
	for j in `grep "\[*\]" $i`
	do
		let x=$x+1
	done

	for k in `grep gpgcheck[[:space:]]*=[[:space:]]*1 $i`
	do
		let y=$y+1
	done 
done
if [ $x -gt $y ]
then
	out "1" $INT
else
	out "0" $INT
fi

INT='1.2.4 Disable the rhnsd Daemon'
/sbin/chkconfig --list rhnsd|grep "on" > /dev/null 
out $(inv $?) $INT

INT='1.2.5 Obtain Software Package Updates with yum'
ret=`/usr/bin/yum check-update |wc -l`
out $ret $INT

INT='1.2.6 Verify Package Integrity Using RPM'
/bin/rpm -qVa 2>&1| awk '$2 != "c" { print $0}' | grep "Unsatisfied dependencies"
out $(inv $?) $INT

INT='1.2.7 Is the system up-to-date ?' 
nb=`/usr/bin/yum check-update |grep -v -e "Loaded plugins" -e "This system" -e "^$"|wc -l`
out $nb $INT

INT='1.2.8 Only RedHat Repositories are used'
x=0
for i in `grep baseurl /etc/yum.conf /etc/yum.repos.d/*|awk -F= '{print $2}'`
do
	if [[ ! $i =~ ftp.redhat.com ]]
	then
		let x=$x+1
	fi
done
out $x $INT

## 1.3 Advanced Intrusion Detection Environment (AIDE) ##
#echo "    1.3 Advanced Intrusion Detection Environment (AIDE)"

INT='1.3.1 Install AIDE'
/bin/rpm -q aide > /dev/null
out $? $INT

INT='1.3.2 Implement Periodic Execution of File Integrity'
/usr/bin/crontab -u root -l 2>/dev/null| grep aide > /dev/null
out $? $INT

## 1.4 Configure SELinux ##
#echo "    1.4 Configure SELinux"

INT='1.4.1 Enable SELinux in /etc/grub.conf'
grep selinux=0 /etc/grub.conf > /dev/null
let x=$(inv $?)
grep enforcing=0 /etc/grub.conf > /dev/null
let x=$x+$(inv $?)
out $x $INT

INT='1.4.2 Set the SELinux State'
grep "SELINUX[[:space:]]*=[[:space:]]*enforcing" /etc/selinux/config > /dev/null
out $? $INT

INT='1.4.3 Set the SELinux Policy'
grep SELINUXTYPE[[:space:]]*=[[:space:]]*targeted /etc/selinux/config > /dev/null
out $? $INT

INT='1.4.4 Remove SETroubleshoot'
/bin/rpm -q setroubleshoot > /dev/null
out $(inv $?) $INT

INT='1.4.5 Remove MCS Translation Service (mcstrans)'
/bin/rpm -q mcstrans > /dev/null
out $(inv $?) $INT

INT='1.4.6 Check for Unconfined Daemons'
ps -eZ | grep -v "tr|ps|egrep|bash|awk"|grep initrc > /dev/null
out $(inv $?) $INT

## 1.5 Secure Boot Settings
#echo "    1.5 Secure Boot Settings"

INT='1.5.1 Set User/Group Owner on /etc/grub.conf' 
stat -L -c "%u %g" /etc/grub.conf | egrep "0 0" > /dev/null 
out $? $INT

INT='1.5.2 Set Permissions on /etc/grub.conf'
stat -L -c "%a" /etc/grub.conf | egrep ".00" > /dev/null
out $? $INT

INT='1.5.3 Set Boot Loader Password'
grep "^password" /etc/grub.conf > /dev/null
out $? $INT

INT='1.5.4 Require Authentication for Single-User Mode'
grep "SINGLE[[:space:]]*=[[:space:]]*[a-zA-Z/]*sulogin" /etc/sysconfig/init > /dev/null
out $x $INT

INT='1.5.5 Disable Interactive Boot'
grep "PROMPT[[:space:]]*=[[:space:]]*no" /etc/sysconfig/init > /dev/null
out $x $INT

## 1.6 Additional Process Hardening ##
#echo "    1.6 Additional Process Hardening"

INT='1.6.1 Restrict Core Dumps'
grep "hard[[:space:]]*core[[:space:]]*0" /etc/security/limits.conf > /dev/null
let x=$?
let x=$x+`sysctl fs.suid_dumpable|awk '{print $3}'`
out $x $INT

INT='1.6.2 Configure ExecShield'
x=`sysctl kernel.exec-shield|awk '{print $3}'`
out $(inv $x) $INT

INT='1.6.3 Enable Randomized Virtual Memory Region Placement'
x=`sysctl kernel.randomize_va_space|awk '{print $3}'`
out $(inv $x) $INT

INT='1.6.4 Use the Latest OS Release'
LATEST="6.4"
x=`cat /etc/redhat-release |awk '{print $7}'`
if [ "$LATEST" == "$x" ]
then
	out "0" $INT
else
	out "1" $INT
fi

### 2 - OS Services ###
echo "### 2 - OS Services"

## 2.1 Remove Legacy Services ##
#echo "    2.1 Remove Legacy Services"

INT='2.1.1 Remove telnet-server'
/bin/rpm -q telnet-server > /dev/null
out $(inv $?) $INT

INT='2.1.2 Remove telnet Clients'
/bin/rpm -q telnet > /dev/null
out $(inv $?) $INT

INT='2.1.3 Remove rsh-server'
/bin/rpm -q rsh-server > /dev/null
out $(inv $?) $INT

INT='2.1.4 Remove rsh'
/bin/rpm -q rsh > /dev/null
out $(inv $?) $INT

INT='2.1.5 Remove NIS Client'
/bin/rpm -q ypbind > /dev/null
out $(inv $?) $INT

INT='2.1.6 Remove NIS Server'
/bin/rpm -q ypserv > /dev/null
out $(inv $?) $INT

INT='2.1.7 Remove tftp'
/bin/rpm -q tftp > /dev/null
out $(inv $?) $INT

INT='2.1.8 Remove tftp-server'
/bin/rpm -q tftp-server > /dev/null
out $(inv $?) $INT

INT='2.1.9 Remove talk'
/bin/rpm -q talk > /dev/null
out $(inv $?) $INT

INT='2.1.10 Remove talk-server'
/bin/rpm -q talk-server > /dev/null
out $(inv $?) $INT

INT='2.1.11 Remove xinetd'
/bin/rpm -q xinetd > /dev/null
out $(inv $?) $INT

INT='2.1.12 Disable chargen-dgram'
/sbin/chkconfig --list chargen-dgram 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='2.1.13 Disable chargen-stream'
/sbin/chkconfig --list chargen-stream 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='2.1.14 Disable daytime-dgram'
/sbin/chkconfig --list daytime-dgram 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='2.1.15 Disable daytime-stream'
/sbin/chkconfig --list daytime-stream 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='2.1.16 Disable echo-dgram'
/sbin/chkconfig --list echo-dgram 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='2.1.17 Disable echo-stream'
/sbin/chkconfig --list echo-stream 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='2.1.18 Disable tcpmux-server'
/sbin/chkconfig --list tcpmux-server 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

### 3 - Special Purpose Services ###
echo "### 3 - Special Purpose Services"

INT='3.1 Set Daemon umask'
grep "umask[[:space:]]*027" /etc/sysconfig/init > /dev/null
out $? $INT
 
INT='3.2 Remove X Windows'
/bin/rpm -q xorg-x11-server > /dev/null
out $(inv $?) $INT

INT='3.3 Disable Avahi Server'
/sbin/chkconfig --list avahi-daemon 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='3.4 Disable Print Server - CUPS'
/sbin/chkconfig --list cups 2>/dev/null|grep "on" > /dev/null
out $(inv $?) $INT

INT='3.5 Remove DHCP Server'
/bin/rpm -q dhcp > /dev/null
out $(inv $?) $INT

INT='3.6 Configure Network Time Protocol (NTP)'
grep -e "restrict" -e "default" /etc/ntp.conf > /dev/null 2>&1
out $? $INT

INT='3.7 Remove LDAP'
/bin/rpm -q openldap-servers > /dev/null
x=$?
/bin/rpm -q openldap-clients > /dev/null
let x=$x+$?
out $(inv $x) $INT

INT='3.8 Disable NFS and RPC'
/sbin/chkconfig --list nfslock 2>/dev/null|grep "on" > /dev/null
x=$?
/sbin/chkconfig --list rpcgssd 2>/dev/null|grep "on" > /dev/null
let x=$x+$?
/sbin/chkconfig --list rpcbind 2>/dev/null|grep "on" > /dev/null
let x=$x+$?
/sbin/chkconfig --list rpcidmapd 2>/dev/null|grep "on" > /dev/null
let x=$x+$?
/sbin/chkconfig --list rpcsvcgssd 2>/dev/null|grep "on" > /dev/null
let x=$x+$?
out $(inv $x) $INT

INT='3.9 Remove DNS Server'
/bin/rpm -q bind > /dev/null
out $(inv $?) $INT

INT='3.10 Remove FTP Server'
/bin/rpm -q vsftpd > /dev/null
x=$?
/bin/rpm -q proftpd > /dev/null
let x=$x+$?
out $(inv $x) $INT

INT='3.11 Remove HTTP Server'
/bin/rpm -q httpd > /dev/null
x=$?
/bin/rpm -q nginx > /dev/null
let x=$x+$?
out $(inv $x) $INT

INT='3.12 Remove Dovecot'
/bin/rpm -q dovecot > /dev/null
out $(inv $?) $INT

INT='3.13 Remove Samba'
/bin/rpm -q samba > /dev/null
x=$?
/bin/rpm -q samba4 > /dev/null
let x=$x+$?
out $(inv $x) $INT

INT='3.14 Remove HTTP Proxy Server'
/bin/rpm -q squid > /dev/null
x=$?
/bin/rpm -q tinyproxy > /dev/null
let x=$x+$?
out $(inv $x) $INT

INT='3.15 Remove SNMP Server'
/bin/rpm -q net-snmp > /dev/null
out $(inv $x) $INT

INT='3.16 Configure Mail Transfer Agent for Local-Only Mode'
grep "^inet_interfaces[[:space:]]*=[[:space:]]*localhost" /etc/postfix/main.cf > /dev/null
out $? $INT

INT='3.17 Set default Runlevel to 3'
rl=`runlevel|awk '{print $2}'`
if [ $rl -eq 3 ]
then
	out "0" $INT
else
	out "1" $INT
fi

### 4 - Network Configuration and Firewalls ###
echo "### 4 - Network Configuration and Firewalls"

## 4.1 - Modify Network Parameters (Host Only) ##
#echo "    4.1 - Modify Network Parameters (Host Only)"

INT='4.1.1 Disable IP Forwarding' 
x=`/sbin/sysctl net.ipv4.ip_forward|awk '{print $3}'`
out $x $INT

INT='4.1.2 Disable Send Packet Redirects'
x=`/sbin/sysctl net.ipv4.conf.all.send_redirects|awk '{print $3}'`
let x=$x+`/sbin/sysctl net.ipv4.conf.default.send_redirects|awk '{print $3}'`
out $x $INT

## 4.2 - Modify Network Parameters (Host and Router) ##
#echo "    4.2 - Modify Network Parameters (Host and Router)"

INT='4.2.1 Disable Source Routed Packet Acceptance'
x=`/sbin/sysctl net.ipv4.conf.all.accept_source_route|awk '{print $3}'`
let x=$x+`/sbin/sysctl net.ipv4.conf.default.accept_source_route|awk '{print $3}'`
out $x $INT

INT='4.2.2 Disable ICMP Redirect Acceptance'
x=`/sbin/sysctl net.ipv4.conf.all.accept_redirects|awk '{print $3}'`
let x=$x+`/sbin/sysctl net.ipv4.conf.default.accept_redirects|awk '{print $3}'`
out $x $INT

INT='4.2.3 isable Secure ICMP Redirect Acceptance'
x=`/sbin/sysctl net.ipv4.conf.all.secure_redirects|awk '{print $3}'`
let x=$x+`/sbin/sysctl net.ipv4.conf.default.secure_redirects|awk '{print $3}'`
out $x $INT

INT='4.2.4 Log Suspicious Packets'
x=$(inv `/sbin/sysctl net.ipv4.conf.all.log_martians|awk '{print $3}'`)
let x=$x+$(inv `/sbin/sysctl net.ipv4.conf.default.log_martians|awk '{print $3}'`)
out $x $INT

INT='4.2.5 Enable Ignore Broadcast Requests'
x=`/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts|awk '{print $3}'`
out $(inv $x) $INT

INT='4.2.6 Enable Bad Error Message Protection'
x=`/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses|awk '{print $3}'`
out $(inv $x) $INT

INT='4.2.7 Enable RFC-recommended Source Route Validation'
x=$(inv `/sbin/sysctl net.ipv4.conf.all.rp_filter|awk '{print $3}'`)
let x=$x+$(inv `/sbin/sysctl net.ipv4.conf.default.rp_filter|awk '{print $3}'`)
out $x $INT

INT='4.2.8 Enable TCP SYN Cookies'
x=`/sbin/sysctl net.ipv4.tcp_syncookies|awk '{print $3}'`
out $(inv $x) $INT

## 4.3 - Wireless Networking ##
#echo "    4.3 - Wireless Networking"

INT='4.3.1 Deactivate Wireless Interfaces'
ifconfig |grep wlan
out $(inv $?) $INT

## 4.4 - Disable IPv6 ##
#echo "    4.4 - Disable IPv6"

# 4.4.1 Configure IPv6

INT='4.4.1.1 Disable IPv6 Router Advertisements'
ret=`/sbin/sysctl -e net.ipv6.conf.all.accept_ra|awk '{print $3}'`
x=${ret:-0}
ret=`/sbin/sysctl -e net.ipv6.conf.default.accept_ra|awk '{print $3}'`
y=${ret:-0}
let x=$x+$y
out $x $INT

INT='4.4.1.2 Disable IPv6 Redirect Acceptance'
ret=`/sbin/sysctl net.ipv6.conf.all.accept_redirect 2>/dev/null|awk '{print $3}'`
x=${ret:-0}
ret=`/sbin/sysctl net.ipv6.conf.default.accept_redirect 2>/dev/null|awk '{print $3}'`
y=${ret:-0}
let x=$x+$y
out $x $INT

INT='4.4.2 Disable IPv6'
grep "NETWORKING_IPV6[[:space:]]*=[[:space:]]*no" /etc/sysconfig/network > /dev/null
x=$?
grep "IPV6INIT[[:space:]]*=[[:space:]]*no" /etc/sysconfig/network > /dev/null
let x=$x+$?
grep "ipv6[[:space:]]*disable[[:space:]]*=[[:space:]]*1" /etc/modprobe.d/*.conf > /dev/null
let x=$x+$?
out $x $INT

## 4.5 - Install TCP Wrappers ##
#echo "    4.5 - Install TCP Wrappers"

INT='4.5.1 Install TCP Wrappers'
/bin/rpm -q tcp_wrappers > /dev/null
out $? $INT

INT='4.5.2 Create /etc/hosts.allow'
if [ -f /etc/hosts.allow ]
then
	grep "^ALL[[:space:]]*:[[:space:]]*[0-9.]*\/[0-9.]*" /etc/hosts.allow > /dev/null
	out $? $INT
else
	out "1" $INT
fi

INT='4.5.3 Verify Permissions on /etc/hosts.allow'
stat -L -c "%a" /etc/hosts.allow|grep 644 > /dev/null
out $? $INT

INT='4.5.4 Create /etc/hosts.deny'
if [ -f /etc/hosts.deny ]
then
	grep "^ALL[[:space:]]*:[[:space:]]*ALL" /etc/hosts.deny > /dev/null
	out $? $INT
else
	out "1" $INT
fi

INT='4.5.5 Verify Permissions on /etc/hosts.deny'
stat -L -c "%a" /etc/hosts.deny|grep 644 > /dev/null
out $? $INT

## 4.6 - Uncommon Network Protocols ##
#echo "    4.6 - Uncommon Network Protocols"

INT='4.6.1 Disable DCCP'
grep "install[[:space:]]*dccp[[:space:]]/bin/true" /etc/modprobe.d/*.conf > /dev/null
out $? $INT

INT='4.6.2 Disable SCTP'
grep "install[[:space:]]*sctp[[:space:]]/bin/true" /etc/modprobe.d/*.conf > /dev/null
out $? $INT

INT='4.6.3 Disable RDS'
grep "install[[:space:]]*rds[[:space:]]/bin/true" /etc/modprobe.d/*.conf > /dev/null
out $? $INT

INT='4.6.4 Disable TIPC'
grep "install[[:space:]]*tipc[[:space:]]/bin/true" /etc/modprobe.d/*.conf > /dev/null
out $? $INT

## 4.6 - Configure IPtables
INT='4.7 Enable IPtables'
chkconfig --list iptables|grep "on" > /dev/null
out $? $INT

INT='4.8 Disable IP6tables'
chkconfig --list ip6tables|grep "on" > /dev/null
out $(inv $?) $INT

### 5 - Logging and Auditing ###
echo "### 5 - Logging and Auditing"

## 5.1 - Configure rsyslog ##
#echo "    5.1 - Configure rsyslog"

INT='5.1.1 Install the rsyslog package'
/bin/rpm -q rsyslog > /dev/null
out $? $INT

INT='5.1.2 Activate the rsyslog Service'
chkconfig --list rsyslog|grep "on" > /dev/null
out $? $INT

# 5.1.3 Configure /etc/rsyslog.conf
out "0" "5.1.3" "TODO"
#x=0
#for i in "auth user kern daemon syslog lpr news uucp local"
#do
#
#done
#do
#	prt=grep $i /etc/rsyslog.conf > /dev/null
#	if [ $? -eq 0 ]
#	then
#		if [[ "$prt" =~ "$i[\.\*]*[[:space:]]/var/log/[a-z]A-Z+" ]]
#	else
#		let x=$x+1
#	fi
#done

INT='5.1.4 Create and Set Permissions on rsyslog Log Files'
files=`grep "IncludeConfig" /etc/rsyslog.conf|awk '{print $2}'`
list="/etc/rsyslog.conf"
for i in $files
do
	if [ -f $i ]
	then
		list="$list $i"
	fi
done
x=0
for i in $list
do
	stat -L -c "%u %g" $i | egrep "0 0" > /dev/null
	let x=$x+$?	
	stat -L -c "%a" $i|grep 600 > /dev/null	
	let x=$x+$?
done
out $x $INT

INT='5.1.5 Configure rsyslog to Send Logs to a Remote Log Host'
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf > /dev/null
out $? $INT

INT="5.1.6 Don't Accept Remote rsyslog Messages Only on Designated Log Hosts"
grep '$ModLoad[[:space:]]*imtcp.so' /etc/rsyslog.conf > /dev/null
out $(inv $?) $INT

# 5.2 Configure System Accounting (auditd)
# 5.2.1 Configure Data Retention
INT='5.2.1.1 Configure Audit Log Storage Size'
grep max_log_file /etc/audit/auditd.conf > /dev/null
out $? $INT

INT='5.2.1.2 Disable System on Audit Log Full'
grep "space_left_action[[:space:]]*=[[:space:]]*email" /etc/audit/auditd.conf > /dev/null
x=$?
grep "action_mail_acct[[:space:]]*=[[:space:]]*root" /etc/audit/auditd.conf > /dev/null
let x=$x+$?
grep "admin_space_left_action[[:space:]]*=[[:space:]]*halt" /etc/audit/auditd.conf > /dev/null
let x=$x+$?
out $x $INT

INT='5.2.1.3 Keep All Auditing Information'
grep "max_log_file_action[[:space:]]*=[[:space:]]*keep_logs" /etc/audit/auditd.conf > /dev/null
out $? $INT

INT='5.2.2 Enable auditd Service'
chkconfig --list auditd|grep "on" > /dev/null
out $? $INT

INT='5.2.3 Enable Auditing for Processes That Start Prior to auditd'
nbk=`grep -v "^#" /etc/grub.conf |grep "kernel"|wc -l`
nba=`grep -v "^#" /etc/grub.conf |grep "kernel.*audit=1"|wc -l`
if [ $nbk -eq $nba ]
then
	out "0" $INT
else
	out "1" $INT
fi

# 5.2.4 Record Events That Modify Date and Time Information
out "0" "5.2.4" "TODO"

# 5.2.5 Record Events That Modify User/Group Information
out "0" "5.2.5" "TODO"

# 5.2.6 Record Events That Modify the System's Network Environment
out "0" "5.2.6" "TODO"

# 5.2.7 Record Events That Modify the System's Mandatory Access
out "0" "5.2.7" "TODO"

# 5.2.8 Collect Login and Logout Events
out "0" "5.2.8" "TODO"

# 5.2.9 Collect Session Initiation Information
out "0" "5.2.9" "TODO"

# 5.2.10 Collect Discretionary Access Control Permission Modification Events
out "0" "5.2.10" "TODO"

# 5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files
out "0" "5.2.11" "TODO"

# 5.2.12 Collect Use of Privileged Commands
out "0" "5.2.12" "TODO"

# 5.2.13 Collect Successful File System Mounts 
out "0" "5.2.13" "TODO"

# 5.2.14 Collect File Deletion Events by User
out "0" "5.2.14" "TODO"

# 5.2.15 Collect Changes to System Administration Scope
out "0" "5.2.15" "TODO"

# 5.2.16 Collect System Administrator Actions
out "0" "5.2.16" "TODO"

# 5.2.17 Collect Kernel Module Loading and Unloading
out "0" "5.2.17" "TODO"

# 5.2.18 Make the Audit Configuration Immutable 
out "0" "5.2.18" "TODO"

INT='5.3 Configure logrotate'
grep '{' /etc/logrotate.d/syslog > /dev/null
out $? $INT

echo "### 6 System Access, Authentication and Authorization"
# 6.1 Configure cron and anacron
INT='6.1.1 Enable anacron Daemon'
/bin/rpm -q cronie-anacron > /dev/null
out $? $INT

INT='6.1.2 Enable crond Daemon'
chkconfig --list crond |grep "on" > /dev/null
out $? $INT

INT='6.1.3 Set User/Group Owner and Permission on /etc/anacrontab'
stat -L -c "%a %u %g" /etc/anacrontab | egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.1.4 Set User/Group Owner and Permission on /etc/crontab'
stat -L -c "%a %u %g" /etc/crontab | egrep ".00 0 0" > /dev/null 
out $? $INT

INT='6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly'
stat -L -c "%a %u %g" /etc/cron.hourly | egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.1.6 Set User/Group Owner and Permission on /etc/cron.daily'
stat -L -c "%a %u %g" /etc/cron.daily | egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly'
stat -L -c "%a %u %g" /etc/cron.weekly | egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly'
stat -L -c "%a %u %g" /etc/cron.monthly | egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.1.9 Set User/Group Owner and Permission on /etc/cron.d'
stat -L -c "%a %u %g" /etc/cron.d | egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.1.10 Restrict at Daemon'
stat -L /etc/at.deny > /dev/null 2>&1
x=$(inv $?)
stat -L -c "%a %u %g" /etc/at.allow 2>/dev/null| egrep ".00 0 0" > /dev/null 2>&1
let x=$x+$?
out $x $INT

INT='6.1.11 Restrict at/cron to Authorized Users'
x=0
if [ -f /etc/cron.allow ]
then
	stat -L -c "%a %u %g" /etc/cron.allow 2>/dev/null| egrep ".00 0 0" > /dev/null
	let x=$x+$?
else
	if [ -f /etc/cron.deny ]
	then
		stat -L -c "%a %u %g" /etc/cron.deny 2>/dev/null| egrep ".00 0 0" > /dev/null
		let x=$x+$?
	else
		let x=$x+1
	fi
fi
if [ -f /etc/at.allow ]
then
	stat -L -c "%a %u %g" /etc/at.allow 2>/dev/null| egrep ".00 0 0" > /dev/null 2>&1
	let x=$x+$?
else
        if [ -f /etc/at.deny ]
        then
		stat -L -c "%a %u %g" /etc/at.deny 2>/dev/null| egrep ".00 0 0" > /dev/null
		let x=$x+$?
        else
		let x=$x+1
        fi
fi
out $x $INT

# 6.2 Configure SSH
INT='6.2.1 Set SSH Protocol to 2'
grep "^Protocol[[:space:]]*2" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.2 Set SSH LogLevel to INFO'
grep "^LogLevel[[:space:]]*INFO" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.3 Set Permissions on /etc/ssh/sshd_config'
stat -L -c "%a %u %g" /etc/ssh/sshd_config 2>/dev/null| egrep ".00 0 0" > /dev/null
out $? $INT

INT='6.2.4 Disable SSH X11 Forwarding'
grep "^X11Forwarding[[:space:]]*no" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.5 Set SSH MaxAuthTries to 4 or Less'
grep "^MaxAuthTries[[:space:]]*4" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.6 Set SSH IgnoreRhosts to Yes'
grep "^IgnoreRhosts[[:space:]]*yes" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.7 Set SSH HostbasedAuthentication to No'
grep "^HostbasedAuthentication[[:space:]]*no" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.8 Disable SSH Root Login'
grep "^PermitRootLogin[[:space:]]*no" /etc/ssh/sshd_config > /dev/null
out $? $INT

INT='6.2.9 Set SSH PermitEmptyPasswords to No'
grep "^PermitEmptyPasswords[[:space:]]*no" /etc/ssh/sshd_config  > /dev/null
out $? $INT

INT='6.2.10 Do Not Allow Users to Set Environment Options'
grep "^PermitUserEnvironment[[:space:]]*no" /etc/ssh/sshd_config  > /dev/null
out $? $INT

INT='6.2.11 Use Only Approved Cipher in Counter Mode'
grep "^Ciphers" /etc/ssh/sshd_config|grep -e aes128-ctr -e aes192-ctr -e aes256-ctr > /dev/null
out $? $INT

INT='6.2.12 Set Idle Timeout Interval for User Login'
grep "^ClientAliveInterval[[:space:]]*300" /etc/ssh/sshd_config > /dev/null
x=$?
grep "^ClientAliveCountMax[[:space:]]*0" /etc/ssh/sshd_config > /dev/null
let x=$x+$?
out $x $INT

INT='6.2.13 Limit Access via SSH'
grep "^AllowUsers" /etc/ssh/sshd_config > /dev/null
if [ $? -eq 1 ]
then
	grep "^AllowGroups" /etc/ssh/sshd_config  > /dev/null
	x=$?
fi
grep "^DenyUsers" /etc/ssh/sshd_config > /dev/null
if [ $? -eq 1 ]
then
	grep "^DenyGroups" /etc/ssh/sshd_config > /dev/null
	let x=$x+$?
fi
out $x $INT

INT='6.2.14 Set SSH Banner'
grep "^Banner" /etc/ssh/sshd_config > /dev/null
out $? $INT

#echo "# 6.3 Configure PAM"
INT='6.3.1 Upgrade Password Hashing Algorithm to SHA-512'
authconfig --test | grep hashing | grep sha512 > /dev/null
out $? $INT

INT='6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib'
grep -v "^#" /etc/pam.d/system-auth| grep pam_cracklib.so |grep try_first_pass |grep "retry[[:space:]]*=[[:space:]]*3" |grep "minlen[[:space:]]*=[[:space:]]*8" |grep "dcredit[[:space:]]*=[[:space:]]*-1" |grep "ucredit[[:space:]]*=[[:space:]]*-1" |grep "ocredit[[:space:]]*=[[:space:]]*-1" |grep "lcredit[[:space:]]*=[[:space:]]*-1" > /dev/null
out $? $INT

INT='6.3.3 Set Lockout for Failed Password Attempts'
grep "^auth.*pam_faillock" /etc/pam.d/password-auth > /dev/null
x=$?
grep "^auth.*pam_unix.so" /etc/pam.d/password-auth | grep "success[[:space:]]*=[[:space:]]*1"
let x=$x+$?
grep "^auth.*pam_faillock" /etc/pam.d/system-auth > /dev/null
let x=$x+$?
grep "^auth.*pam_unix.so" /etc/pam.d/system-auth | grep "success[[:space:]]*=[[:space:]]*1"
let x=$x+$?
out $x $INT

INT='6.3.4 Limit Password Reuse'
grep "^password.*pam_unix" /etc/pam.d/system-auth| grep "remember[[:space:]]*=[[:space:]]*5" > /dev/null
out $? $INT

INT='6.4 Restrict root Login to System Console'
x=`grep -v -e "^console" -e "^vc" -e "^tty" /etc/securetty |wc -l`
out $x $INT

INT='6.5 Restrict Access to the su Command'
ret=`grep "^auth.*pam_wheel.so" /etc/pam.d/su`
x=$?
group="wheel"
[[ "$ret" =~ group=([^ .]*)( |$) ]] && group=${BASH_REMATCH[1]}
grep "^$group" /etc/group > /dev/null
let x=$x+$?
out $x $INT

INT='6.6 Restrict root Login for ftp'
#auth required /lib/security/pam_listfile.so item=user sense=deny file=/etc/ftpusers.deny onerr=succeed
x=0
for i in `find /etc/pam.d -name *ftp*`
do
	grep pam_listfile.*sense=deny.*file= $i > /dev/null	
	let x=$x+$?
done
out $x $INT

INT='6.7 Restrict root Login from X'
x=0                                
for i in `find /etc/pam.d | grep -e kdm -e xdm -e gdm`
do     
        grep pam_listfile.*sense=deny.*file= $i > /dev/null 
        let x=$x+$?
done
out $x $INT

echo "### 7 User Accounts and Environment"
# 7.1 Set Shadow Password Suite Parameters (/etc/login.defs) 
INT='7.1.1 Set Password Expiration Days'
grep "^PASS_MAX_DAYS[[:space:]]*90" /etc/login.defs > /dev/null
out $? $INT

INT='7.1.2 Set Password Change Minimum Number of Days'
grep "^PASS_MIN_DAYS[[:space:]]*7" /etc/login.defs > /dev/null
out $? $INT

INT='7.1.3 Set Password Expiring Warning Days'
grep "^PASS_WARN_AGE[[:space:]]*7" /etc/login.defs > /dev/null
out $? $INT

INT='7.2 Disable System Accounts'
ret=`egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}'|wc -l`
out $ret $INT

INT='7.3 Set Default Group for root Account'
ret=`grep "^root:" /etc/passwd | cut -f4 -d:`
out $ret $INT

INT='7.4 Set Default umask for Users'
grep "^umask[[:space:]]*077" /etc/bashrc > /dev/null
x=$?
grep "^umask[[:space:]]*077" /etc/profile > /dev/null
let x=$x+$?
out $x $INT

INT='7.5 Lock Inactive User Accounts'
ret=`useradd -D | grep "INACTIVE"`
[[ "$ret" =~ INACTIVE=([\-0-9]*)$ ]] && age=${BASH_REMATCH[1]}
if [ $age -le 35 ] && [ $age -gt 0 ]
then
	out 0 $INT
else
	out 1 $INT
fi

INT='7.6 Trap SIGHUP, SIGINT, SIGQUIT and SIGTERM for console'
grep trap.*1.*2.*3.*15 /etc/profile > /dev/null
out $? $INT

echo "### 8 Warning Banners"
INT='8.1 Set Warning Banner for Standard Login Services'
stat -L -c "%a %u %g" /etc/motd | egrep "644 0 0" > /dev/null
x=$?
stat -L -c "%a %u %g" /etc/issue | egrep "644 0 0" > /dev/null
let x=$x+$?
stat -L -c "%a %u %g" /etc/issue.net | egrep "644 0 0" > /dev/null
let x=$x+$?
out $x $INT

INT='8.2 Remove OS Information from Login Warning Banners'
egrep '(\\v|\\r|\\m|\\s)' /etc/issue > /dev/null
x=$(inv $?)
egrep '(\\v|\\r|\\m|\\s)' /etc/motd > /dev/null
let x=$x+$(inv $?)
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net > /dev/null
let x=$x+$(inv $?)
out $x $INT

INT='8.3 Set GNOME Warning Banner'
x=0
rpm -q gdm > /dev/null
if [ $? -eq 0 ]
then
	ret=`gconftool-2 --get /apps/gdm/simple-greeter/banner_message_text`
	[[ $ret =~ "No value set for" ]] && x=1
else
	x=0
fi
out $x $INT

echo "### 9 System Maintenance"
#echo "9.1 Verify System File Permissions"
INT='9.1.1 Verify System File Permissions'
x=0
for i in `rpm -Va --nomtime --nosize --nomd5 --nolinkto|awk '{print $NF}'`
do
	grep $i $0 >/dev/null
	if [ $? -ne 0 ]
	then
		let x=$x+1
	fi
done
out $x $INT

INT='9.1.2 Verify Permissions on /etc/passwd'
stat -L -c "%a" /etc/passwd | egrep "644" > /dev/null
out $? $INT

INT='9.1.3 Verify Permissions on /etc/shadow'
stat -L -c "%a" /etc/shadow | egrep "0" > /dev/null
out $? $INT

INT='9.1.4 Verify Permissions on /etc/gshadow'
stat -L -c "%a" /etc/gshadow | egrep "0" > /dev/null
out $? $INT

INT='9.1.5 Verify Permissions on /etc/group'
stat -L -c "%a" /etc/group | egrep "644" > /dev/null
out $? $INT

INT='9.1.6 Verify User/Group Ownership on /etc/passwd' 
stat -L -c "%u %g" /etc/group | egrep "0 0" > /dev/null
out $? $INT

INT='9.1.7 Verify User/Group Ownership on /etc/shadow'
stat -L -c "%u %g" /etc/group | egrep "0 0" > /dev/null
out $? $INT

INT='9.1.8 Verify User/Group Ownership on /etc/gshadow'
stat -L -c "%u %g" /etc/group | egrep "0 0" > /dev/null
out $? $INT

INT='9.1.9 Verify User/Group Ownership on /etc/group'
stat -L -c "%u %g" /etc/group | egrep "0 0" > /dev/null
out $? $INT

INT='9.1.10 Find World Writable Files'
ret=`df --local -P|awk {'if (NR!=1) print $NF'} |xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null|wc -l`
out $ret $INT

INT='9.1.11 Find Un-owned Files and Directories'
ret=`df --local -P|awk {'if (NR!=1) print $NF'} |xargs -I '{}' find '{}' -xdev -nouser|wc -l`
out $ret $INT

INT='9.1.12 Find Un-grouped Files and Directories'
ret=`df --local -P|awk {'if (NR!=1) print $NF'} |xargs -I '{}' find '{}' -xdev -nogroup|wc -l`
out $ret $INT

INT='9.1.13 Find SUID System Executables'
ret=`df --local -P|awk {'if (NR!=1) print $NF'} |xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null|wc -l`
out $ret $INT

INT='9.1.14 Find SGID System Executables'
ret=`df --local -P|awk {'if (NR!=1) print $NF'} |xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null|wc -l`
out $ret $INT

#echo "9.2 Review User and Group Settings"
INT='9.2.1 Ensure Password Fields are Not Empty'
ret=`/bin/awk -F: '($2 == "" ) { print $1 }' /etc/shadow |wc -l`
out $ret $INT

INT='9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File '
/bin/grep '^+:' /etc/passwd
out $(inv $?) $INT

INT='9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File'
/bin/grep '^+:' /etc/shadow
out $(inv $?) $INT

INT='9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File'
/bin/grep '^+:' /etc/group
out $(inv $?) $INT

INT='9.2.5 Verify No UID 0 Accounts Exist Other Than root'
ret=`/bin/awk -F: '($3 == 0) { print $1 }' /etc/passwd |grep -v root |wc -l`
out $ret $INT

#INT='9.2.6 Ensure root PATH Integrity'
INT='9.2.6.1 root PATH does not contain any empty directory'
echo $PATH |grep "::" > /dev/null
out $(inv $?) $INT

INT='9.2.6.2 root PATH does not contain trailing ":"'
echo $PATH |grep ":$" > /dev/null
out $(inv $?) $INT

INT='9.2.6.3 root PATH contains current directory'
echo $PATH |grep -P "(^|:)\.(:|$)" > /dev/null
out $(inv $?) $INT

INT='9.2.6.4 Permissions of root PATH directories'
p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
x=0
for i in $p
do
	if [ -d $i ]; then
                dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
                if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
			let x=$x+1
                fi
                if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
			let x=$x+1
                fi
                if [ "`stat -L -c "%u" $i`" != "0" ] ; then
			let x=$x+1
                fi
        else   
		let x=$x+1
        fi
done
out $x $INT

INT='9.2.7 Check Permissions on User Home Directories'
x=0
for dir in `egrep -v '(root|halt|sync|shutdown)' /etc/passwd |awk -F: '($7 != "/sbin/nologin") { print $6 }'`
do
	dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
	if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
		let x=$x+1
	fi
	if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
		let x=$x+1
	fi
	if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
		let x=$x+1
	fi
	if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
		let x=$x+1
	fi
done
out $x $INT

INT='9.2.8 Check User Dot File Permissions'
x=0
for dir in `egrep -v '(root|halt|sync|shutdown)' /etc/passwd |awk -F: '($7 != "/sbin/nologin") { print $6 }'`
do
	for file in $dir/.[A-Za-z0-9]*
	do
		if [ ! -h "$file" -a -f "$file" ]
		then
			fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
			if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
			then
				let x=$x+1
			fi
			if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
			then
				let x=$x+1
			fi
		fi
	done
done
out $x $INT

INT='9.2.9 Check Permissions on User .netrc'
x=0    
for file in `egrep -v '(root|sync|halt|shutdown)' /etc/passwd |awk -F: '($7 != "/sbin/nologin") { print $6 "/.netrc" }'`
do
	if [ -f $file ]; then
		stat -L -c "%a" $file|grep ".00" > /dev/null
		let x=$x+$?
	fi
done
out $x $INT

INT='9.2.10 Check for Presence of User .rhosts Files'
x=0
for file in `egrep -v '(root|sync|halt|shutdown)' /etc/passwd |awk -F: '($7 != "/sbin/nologin") { print $6 "/.rhosts" }'`
do
	if [ ! -h "$file" -a -f "$file" ]; then
		let x=$x+1
	fi
done
out $x $INT

INT='9.2.11 Check Groups in /etc/passwd'
x=0
for i in $(cut -s -d: -f4 /etc/passwd | sort -u )
do
	grep -q -P "^.*?:x:$i:" /etc/group
	if [ $? -ne 0 ]
	then
		let x=$x+1
	fi
done
out $x $INT

INT='9.2.12 Check That Users Are Assigned Valid Home Directories'
x=0
awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd| while read user uid dir; do
if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
	let x=$x+1
fi
done
out $x $INT

INT='9.2.13 Check User Home Directory Ownership'
x=0
awk -F: '{ print $1 " " $3 " " $6 }' /etc/passwd| while read user uid dir; do
if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
	owner=$(stat -L -c "%U" "$dir")
	if [ "$owner" != "$user" ]; then
		let x=$x+1
	fi
fi
done
out $x $INT

INT='9.2.14 Check for Duplicate UIDs'
ret=`cut -f3 -d: /etc/passwd|sort|uniq -c|sed 's/^[ ]*//'|grep -v ^1|wc -l`
out $ret $INT

INT='9.2.15 Check for Duplicate GIDs'
ret=`cut -f3 -d: /etc/group|sort|uniq -c|sed 's/^[ ]*//'|grep -v ^1|wc -l`
out $ret $INT

INT='9.2.16 Check That Reserved UIDs Are Assigned to System Accounts '
x=0
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
for i in `/bin/awk -F: '($3 < 500) { print $1 }' /etc/passwd`
do
	echo $defUsers|grep $i > /dev/null
	let x=$x+$?
done
out $x $INT

INT='9.2.17 Check for Duplicate User Names'
ret=`cut -f1 -d: /etc/passwd|sort|uniq -c|sed 's/^[ ]*//'|grep -v ^1|wc -l`
out $ret $INT

INT='9.2.18 Check for Duplicate Group Names'
ret=`cut -f1 -d: /etc/group|sort|uniq -c|sed 's/^[ ]*//'|grep -v ^1|wc -l`
out $ret $INT

INT='9.2.19 Check for Presence of User .netrc Files'
x=0
for dir in `awk -F: '{ print $6 }' /etc/passwd`; do
	if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
		let x=$x+1
	fi
done
out $x $INT

INT='9.2.20 Check for Presence of User .forward Files'
x=0
for dir in `awk -F: '{ print $6 }' /etc/passwd`; do
        if [ ! -h "$dir/.forward" -a -f "$dir/.iforward" ]; then
                let x=$x+1
        fi
done
out $x $INT

echo "### 10 OMT Specific"
INT='10.1 root account is only used from VLAN 200'
x=0
for i in `last|awk {'if ($1=="root") print $3}'|cut -f3 -d.`
do
	if [ "$i" != "200" ]
	then
		let x=$x+1
	fi
done
out $x $INT

INT='10.2 Check "From" statement in authorized_keys files'
users=`egrep -v '(root|halt|sync|shutdown)' /etc/passwd |awk -F: '($7 != "/sbin/nologin") { print $1 }'`
ret=`grep ^AuthorizedKeysFile /etc/ssh/sshd_config|awk '{print $2}'`
if [ $? -ne 0 ]
then
        ret=".ssh/authorized_keys"
fi
if [[ $ret =~ (\%[a-z]) ]]
then
        case ${BASH_REMATCH[1]} in
        "%u")   x=0
                for user in $users
                do
                        auth_file=`echo $ret| sed s/\%u/$user/`
                        if [ -f $auth_file ]
                        then
                                err=`grep "^from=" $auth_file`
                                if [ $? -ne 0 ]
                                then
                                        let x=$x+1
                                fi
                        fi
                done
                ;;
        "%h")   x=0
                for user in $users
                do
                        home1=`grep "^$user:" /etc/passwd|awk -F: '{print $6}'`
                        home=`echo $home1 |sed "s/\//\\\\\\\\\//g"`
                        auth_file=`echo $ret| sed s/\%h/$home/`
                        if [ -f $auth_file ]
                        then
                                err=`grep "^from=" $auth_file`
                                if [ $? -ne 0 ]
                                then
                                        let x=$x+1
                                fi
                        fi
                done
                ;;
        *)      exit 0
                ;;
        esac
else
        x=0
        for user in $users
        do
                home=`grep "^$user:" /etc/passwd|awk -F: '{print $6}'`
                if [ -f $home/.ssh/authorized_keys ]
                then
                        ret=`grep "^from=" $home/.ssh/authorized_keys`
                        if [ $? -ne 0 ]
                        then
                                let x=$x+1
                        fi
                fi
        done
fi
out $x $INT

#echo "10.3 Verify SNMPD configuration"

INT='10.3.1 Verify that syslocation is provided'
grep -i "^syslocation" /etc/snmp/snmpd.conf > /dev/null
out $? $INT

INT='10.3.2 Verify that syscontact is provided'
grep -i "^syscontact" /etc/snmp/snmpd.conf > /dev/null
out $? $INT

#echo "10.4 Verify NFS Server configuration"

if [ -f /etc/exports ]
then

INT='10.4.1 Do not use "no_root_squash" NFS option'
grep "no_root_squash" /etc/exports > /dev/null
out $(inv $?) $INT

INT='10.4.2 Check for NFS syntax errors'
grep "[^0-9^a-z](" /etc/exports
out $(inv $?) $INT

fi

#echo "10.5 Verify NFS CLient configuration"

INT='10.5.1 Check for nosuid nfs client mount option in /etc/fstab'
x=0
for i in  `grep nfs /etc/fstab`
do
	echo $i| grep nosuid > /dev/null
	let x=$x+$? 
done
out $x $INT

INT='10.5.2 Check for nodev nfs client mount option in /etc/fstab'
x=0
for i in  `grep nfs /etc/fstab`
do
        echo $i| grep nodev > /dev/null
        let x=$x+$?
done
out $x $INT

if [ -f /etc/auto.master ]
then
	LIST=`grep -v "^#" /etc/auto.master|grep -v "^+"|awk '{print $2}'|grep -v "^-"`
	if [ -d /etc/auto.master.d ]
	then
		LIST=`echo $LIST;  find /etc/auto.master.d -maxdepth 1 -type f`
	fi

INT='10.5.3 Check for nosuid nfs client mount option in autofs'
x=0
for i in $LIST
do
	for j in `grep nfs $i`
	do
		echo $i| grep nosuid > /dev/null
       		let x=$x+$?	
	done
done
out $x $INT

INT='10.5.4 Check for nodev nfs client mount option in autofs'
x=0
for i in $LIST
do
	for j in `grep nfs $i`
       	do
               	echo $i| grep nodev > /dev/null
               	let x=$x+$?
       	done
done
out $x $INT

fi

/bin/rpm -q httpd > /dev/null
if [ $? -eq 0 ]
then

LIST="/etc/httpd/conf/httpd.conf"
LIST=`echo $LIST; grep "^Include" httpd.conf |awk '{print "/etc/httpd/"$2}'`

INT='10.6.1 Check ServerTokens Apache directive'
grep "^ServerTokens[[:space:]]*Prod" /etc/httpd/conf/httpd.conf > /dev/null
out $? $INT

INT='10.6.2 Check ServerSignature Apache directive'
grep "^ServerSignature[[:space:]]*Off" /etc/httpd/conf/httpd.conf > /dev/null
out $? $INT

INT='10.6.3 Disable UserDir'
grep "^[[:space:]]*UserDir[[:space:]]*disable" /etc/httpd/conf/httpd.conf > /dev/null
out $? $INT

INT='10.6.4 Check for permissive AllowOverride'
x=0
for i in $LIST
do
	grep "^[[:space:]]*AllowOverride[[:space:]][^None]" $i > /dev/null
	let x=$x+$(inv $?)
done
out $x $INT

INT='10.6.5 Apache server has its own user'
grep "^User[[:space:]][apache|www-data|httpd]" /etc/httpd/conf/httpd.conf > /dev/null
out $? $INT

INT='10.6.6 Apache server has its own group'
grep "^Group[[:space:]][apache|www-data|httpd]" /etc/httpd/conf/httpd.conf > /dev/null
out $? $INT

INT='10.6.7 No usage of +Indexes options'
for i in $LIST
do
	grep "^[[:space:]]*Options[[:space:]]*[^-][+]*Indexes" $i > /dev/null
	let x=$x+$(inv $?)
done
out $x $INT

INT='10.6.8 No usage of +Includes options'
for i in $LIST
do
        grep "^[[:space:]]*Options[[:space:]]*[^-][+]*Includes" $i > /dev/null
        let x=$x+$(inv $?)
done
out $x $INT

INT='10.6.9 No usage of +ExecCGI options'
for i in $LIST
do
        grep "^[[:space:]]*Options[[:space:]]*[^-][+]*ExecCGI" $i > /dev/null
        let x=$x+$(inv $?)
done
out $x $INT

INT='10.6.10 No usage of +FollowSymLinks options'
for i in $LIST
do
        grep "^[[:space:]]*Options[[:space:]]*[^-][+]*FollowSymLinks" $i > /dev/null
        let x=$x+$(inv $?)
done
out $x $INT

INT='10.6.11 Apache runs mod_security'
grep "^LoadModule.*mod_security2.so$" /etc/httpd/conf/httpd.conf > /dev/null
out $? $INT

INT='10.6.12 Timeout is under 300'
tmt=`grep "^Timeout[[:space:]]" /etc/httpd/conf/httpd.conf| awk '{print $2}'`
if [ $tmt -lt 300 ]
then
	out 0 $INT
else
	out 1 $INT
fi

INT='10.6.13 Do not load cgi module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep cgi_module >/dev/null
out $(inv $?) $INT

INT='10.6.14 Do not load userdir module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep userdir_module >/dev/null
out $(inv $?) $INT

INT='10.6.15 Do not load dav module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep dav_module >/dev/null
out $(inv $?) $INT

INT='10.6.16 Do not load dav_fs module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep dav_fs_module >/dev/null
out $(inv $?) $INT

INT='10.6.17 Do not load info module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep info_module >/dev/null
out $(inv $?) $INT

INT='10.6.18 Do not load autoindex module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep autoindex_module >/dev/null
out $(inv $?) $INT

INT='10.6.19 Do not load suexec module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep suexec_module >/dev/null
out $(inv $?) $INT

INT='10.6.20 Do not load mysql_auth module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep mysql_auth_module >/dev/null
out $(inv $?) $INT

INT='10.6.21 Do not load proxy_ftp module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep proxy_ftp_module >/dev/null
out $(inv $?) $INT

INT='10.6.22 Do not load autoindex module'
/usr/sbin/apachectl -t -D DUMP_MODULES 2>&1| grep autoindex_module >/dev/null
out $(inv $?) $INT

fi

INT='10.7.1 DROP as default iptables INPUT policy'
iptables -L INPUT| head -1| grep DROP >/dev/null
out $? $INT

INT='10.7.2 DROP as default iptables OUTPUT policy'
iptables -L OUTPUT| head -1| grep DROP >/dev/null
out $? $INT

INT='10.7.3 DROP as default iptables FORWARD policy'
iptables -L FORWARD| head -1| grep DROP >/dev/null
out $? $INT

INT='10.8.1 Check that screen is installed'
/bin/rpm -q screen > /dev/null
out $? $INT

INT='10.9.1 Check that AD auth is used'
/bin/rpm -q krb5-workstation > /dev/null
x=$?
/bin/rpm -q pam_krb5 > /dev/null
let x=$x+$?
out $x $INT

INT='10.9.2 OMT Domain comtroller is used'
if [ -f /etc/krb5.conf ]
then
	grep "CORP.OMT.LCL" /etc/krb5.conf >/dev/null
	x=$?
else
	x=1
fi
out $x $INT


echo
echo " ==> Score: $score"
echo
