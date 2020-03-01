#!/bin/bash
# !!! WILL ONLY WORK WITH BASH !!! - needs bash substring facility
# ======================================================================
#
# collect_server_details.sh
#
# Part of the server security checking suite.
# This script must be run as the root user to ensure
# it can transverse all filesystems and access all files.
#
# This script collects server detsils. These then need to
# be scp'd or ftp'd to the central reporting server for
# processing.
#
# useage: collect_server_details.sh [ optional parameters ] 
#         optional parameters may be any of the below
#            --scanlevel=N              default is unlimited full scan
#            --backup-etc=yes|no        default is yes
#            --record-packages=yes|no   default is yes
#            --hwlost=yes|no            default is yes
#
# Parameters:
#  The optional --scanlevel=N controls the number of
#  directory levels that will be recursed when doing
#  system file ownership and security checks. If not 
#  provided every system directory will be followed to
#  its end. This should be alowed to default at least
#  once every few months, and ALWAYS ALLOWED TO DEFAULT
#  the first time you run the script and until you have
#  the violations under control.
#  Periodically full scan anyway as users may hide suid
#  files well down a directory path chain.
#
# Notes: output is to the working directory.
#
# 2008/07/03 - added sshd config and banner capture
# 2010/09/22 - added dmidecode and lshw steps to obtain the
#              server hardware profile, slot usage and installed
#              devices (as part of the configuration capture not
#              as a security check section).
# 2010/09/27 - added TCPV6+UDPV6 (basic detection on :: in the netstat
#              as the V6 entries were causing false alerts so I had to
#              keep the V6 entries away from the V4 ones.
# 2014/09/15 - noticed under f20 a find on -perms +6000 is no longer  
#              supported. had to change to seperate find -4000 and -2000
#              steps in the suid file search
# 2019/12/20 - clean ups and also fixed tcp6/udp6 capture, also dmidecode
#              was being run twice so removed the duplicate in the 
#              hardware info collection step.
# 2020/02/17 - move rpm output listing to a seperate file instead of     
#              including as 'tagged' lines in main file to be processed.
# 2020/02/20 - changed parm input handling, etc tarfile backup, rpm list
#              and hardware listing now optional. Still defaulting to yes
#              for backward compatibility.       
#
# ======================================================================
MAX_SYSSCAN=""            # default is no limit parameter
SCANLEVEL_USED="FullScan" # default scanlevel status for collection file
BACKUP_ETC="yes"          # default is to tar up etc
BACKUP_RPMLIST="yes"      # default is to create a rpm package list
DO_HWLIST="yes"           # default is to create the hardware listing

while [[ $# -gt 0 ]];
do
   parm=$1
   key=`echo "${parm}" | awk -F\= {'print $1'}`
   value=`echo "${parm}" | awk -F\= {'print $2'}`
   case "${key}" in
      "--scanlevel")  testvar=`echo "${value}" | sed 's/[0-9]//g'`  # strip out all numerics
                      if [ "${testvar}." != "." ];
                      then
                         echo "*error* the --scanlevel value provided is not numeric"
                         exit 1
                      fi
                      SCANLEVEL_USED="${value}"
                      MAX_SYSSCAN="-maxdepth ${value}"
                      shift
                      ;;
      "--backup-etc") if [ "${value}." != "yes." -a "${value}." != "no." ];
                      then
                         echo "*error* the --backup-etc value provided is not yes or no"
                         exit 1
                      fi
                      BACKUP_ETC="${value}"
                      shift
                      ;;
      "--record-packages") if [ "${value}." != "yes." -a "${value}." != "no." ];
                      then
                         echo "*error* the --record-packages value provided is not yes or no"
                         exit 1
                      fi
                      DO_HWLIST="${value}"
                      shift
                      ;;
      "--hwlist")     if [ "${value}." != "yes." -a "${value}." != "no." ];
                      then
                         echo "*error* the --hwlist value provided is not yes or no"
                         exit 1
                      fi
                      DO_HWLIST="${value}"
                      shift
                      ;;
      *)              echo "Unknown paramater value ${key}"
                      echo "Syntax:$0 [--scanlevel=<number>] [--backup-etc=yes|no] [--record-packages=yes|no] [--hwlist=yes|no]"
                      echo "Please read the documentation."
                      exit 1
                      ;;
   esac
done

timenow=`date`
echo "Start time: ${timenow}"
LOGDIR=`pwd`

# The filenames we need for output, erase if a rerun
myhost=`hostname | awk -F. '{print $1'}`   # if hostname.xx.xx.com only want hostname
LOGFILE="${LOGDIR}/secaudit_${myhost}.txt"
ETCTARFILE="${LOGDIR}/etcfiles_${myhost}.tar"   # if we are backing up etc
HWFILE="${LOGDIR}/hwinfo_${myhost}.txt"
RPMFILE="${LOGDIR}/packagelist_${myhost}.txt"
if [ -f ${LOGFILE} ];
then
   rm -f ${LOGFILE}
fi
if [ -f ${ETCTARFILE} ];
then
   rm -f ${ETCTARFILE}
fi

# ======================================================================
#                           Helper tools
# ======================================================================
record_file() {
   key="$1"
   file="$2"
   if [ -f ${file} ];
   then
      cat ${file} | while read dataline
      do
         echo "${key}=${dataline}" >> ${LOGFILE}
      done
   fi
} # record_file

# output ls -la of dir + NA as expected owner
# Notes, added extra = to output as some filenames having spaces
# in the name threw out the data processing. The processing now
# expects and handles the second =.
find_perms_under_dir() {
   key="$1"
   startdir="$2"
   expected_owner="$3"
   if [ "${expected_owner}." = "." ];
   then
      expected_owner="NA"  # can be any owner
   fi
   find ${startdir} ${MAX_SYSSCAN} -mount -type f -exec ls -la {} \; | grep -v "\/tmp\/" | tr "\=" "-" | while read dataline
   do
      echo "${key}=${dataline}=${expected_owner}" >> ${LOGFILE}
   done
} # fine_perms_under_dir

find_perms_under_system_dir() {
   key="$1"
   startdir="$2"
   find_perms_under_dir "${key}" "${startdir}" "SYSTEM"
} # find_perms_under_system_dir

# output ls -la of dir + expected-owner
find_dir_perm() {
   key="$1"
   dirname="$2"
   expected_user="$3"
   optdata="$3"  # expected user generally
   if [ -d ${dirname} ]; # check, some user dirs may be missing
   then
      # The below works fine on the command line, not in a script.
      # dir_perms=`ls -la ${dirname} | grep " .\/" | awk {'print $1":"$3'}`
      # cmdlind gives dirs as ./ and ../, script as . and ..
      # however . is a wildcard in grep, so we can't filter on it
      # Instead, have to ger dirname and basename parts and grep that way
      dirbit=`dirname ${dirname}`
      finddir=`basename ${dirname}`
      # have to do more matching to catch things like uucp and uucppublic causing two matches
      ls -la ${dirbit} | grep " ${finddir}" | while read searching
      do
         testvar=`echo "${searching}" | awk {'print $9'}`
         if [ "${testvar}." = "${finddir}." ];
         then
            searching=`echo "${searching}" | tr "\=" "-"`
            echo "${key}=${searching}=${expected_user} ${optdata}" >> ${LOGFILE}
         fi
      done
   else
      # Build a dummy ls -la line
      echo "${key}=MISSING 1 MISSING MISSING 0 YYYY MM DD ${dirname} ${expected_user}=${expected_user} ${optdata}" >> ${LOGFILE}
   fi
} # find_dir_perm

# Find the permissions of a file. If the filename passed is a
# directory recurse down files under the directory.
# output ls -la of file + expected-owner
find_file_perm() {
   key="$1"
   fname="$2"
   expected_owner="$3"
   optdata="$4"
   if [ -d ${fname} ];
   then
      find ${fname} | while read fname2
      do
         # Important, the find also returns the directory name we have just
         # asked for a find on, and endless loop if we recurs on that so check
         # for it (yes, linux allows find <dir>/* which stops that, but I want
         # to make this portable to non-linux also at some point).
         if [ "${fname2}." != "${fname}." ];   # do not recurse the directory name we are finding on yet again (loop time)
         then
            find_file_perm "${key}" "${fname2}" "${expected_owner}" "${optdata}"
         fi
      done
   else
      tempvar=`ls -la ${fname}`
      # Added for cron jobs, the filename passed from those
      # data collections may not be a full path name but
      # could be using the search path, so try to locate it.
      testresult=$?
      if [ "${testresult}." = "1." ]
      then
         echo "No ${fname}, locating with which"
         fname2=`which ${fname}`
         if [ "${fname2}." != "." ];
         then
            echo "OK, found ${fname2}"
            tempvar=`ls -la ${fname2}`
         else
            echo "Locate failed, expect an error in processing for ${fname}"
         fi
      fi
      # Replace any = in the filename with -, we use = as a delimiter
      tempvar=`echo "${tempvar}" | tr "\=" "-"`
      if [ "${tempvar}." = "." ];
      then
         echo "*WARN* Error locating ${fname} for cron check, skipped"
      else
         echo "${key}=${tempvar}=${expected_owner} ${optdata}" >> ${LOGFILE}
      fi
   fi
} # find_file_perm

# Ensure at least $2 days of data is recorded in the filename
# provided. It is acceptable for the data to be retained in
# archived files managed by a log roller process, but in that
# case we can only go by the last modified date of the log
# archive itself in determining age.
require_file() {
   fname="$1"
   days_needed="$2"
   archive_suffix="$3"
   ls -la ${fname} | while read dataline
   do
       echo "REQD_FILE=${days_needed};${dataline}" >> ${LOGFILE}
   done
   ls -la ${fname}*${archive_suffix} | while read dataline
   do
       echo "REQD_FILE=${days_needed};${dataline}" >> ${LOGFILE}
   done
} # require_file

# ======================================================================
# Record the server details
# ======================================================================
myhost=`hostname`
mydate=`date`
osversion=`uname -r`
ostype=`uname -s`
echo "TITLE_HOSTNAME=${myhost}" >> ${LOGFILE}
echo "TITLE_CAPTUREDATE=${mydate}" >> ${LOGFILE}
echo "TITLE_OSVERSION=${osversion}" >> ${LOGFILE}
echo "TITLE_OSTYPE=${ostype}" >> ${LOGFILE}
echo "TITLE_FileScanLevel=${SCANLEVEL_USED}" >> ${LOGFILE}
echo "TITLE_ExtractVersion=0.05" >> ${LOGFILE}

# ======================================================================
# Collect User Details and key system defaults.
# ======================================================================
record_file PASSWD_FILE /etc/passwd           # user details
record_file PASSWD_SHADOW_FILE /etc/shadow    # password and expiry details
record_file FTPUSERS_FILE /etc/ftpusers       # users that cannot use ftp
record_file LOGIN_DEFS /etc/login.defs        # passwd maxage, minlen etc

# ======================================================================
# Collect General operating system files and optional system files.
# Assumes /etc is under the root directory
#
# MODIFIED 2008/07/05 - bugger, I built a new system with just one
#                       huge slice and put everything in it, so then
#                       the assumption that all files in the / slice
#                       were root files went belly up (ie: all the stuff
#                       in /home had violations). So can no longer scan
#                       from /, so specify all thr system file directories.
# ======================================================================
#find_perms_under_system_dir PERM_SYSTEM_FILE /
find_perms_under_system_dir PERM_SYSTEM_FILE /bin
find_perms_under_system_dir PERM_SYSTEM_FILE /boot
find_perms_under_system_dir PERM_SYSTEM_FILE /dev
find_perms_under_system_dir PERM_SYSTEM_FILE /etc
find_perms_under_system_dir PERM_SYSTEM_FILE /lib
find_perms_under_system_dir PERM_SYSTEM_FILE /opt
find_perms_under_system_dir PERM_SYSTEM_FILE /sbin
find_perms_under_system_dir PERM_SYSTEM_FILE /sys
find_perms_under_system_dir PERM_SYSTEM_FILE /usr
find_perms_under_system_dir PERM_SYSTEM_FILE /var

# ======================================================================
# Collect perms of user directories.
# ======================================================================
cat /etc/passwd | while read dataline
do
   userdetails=`echo "${dataline}" | awk -F: {'print $6" "$1'}` # dir and user
   find_dir_perm "PERM_HOME_DIR" ${userdetails}   # pass dir and user with key
done

# ======================================================================
# Find all SUID fileser directories.
# From F20 (19?) -perm +6000 is npr permitted to find both,
# we have to seperately search on -4000 and -2000 now
# ======================================================================
find / -type f -perm -4000 -exec ls -la {} \;  | while read dataline
do
   echo "SUID_FILE=${dataline}" >> ${LOGFILE}
done
find / -type f -perm -2000 -exec ls -la {} \;  | while read dataline
do
   echo "SUID_FILE=${dataline}" >> ${LOGFILE}
done

# ======================================================================
# Collect perms of key files.
# ======================================================================
find_file_perm PERM_SHADOW_FILE /etc/shadow "root"

# N/A, I use postfix
# find_file_perm PERM_SENDMAIL_FILE /etc/sendmail.cf

# ======================================================================
# Collect permissions of jobs run by cron
# ======================================================================
# Anacron if present
if [ -f /etc/anacrontab ];
then
   grep "run-parts" /etc/anacrontab | grep -v "^#" | while read dataline
   do
         fname=`echo "${dataline}" | awk {'print $5'}`
         find_file_perm PERM_CRON_JOB_FILE ${fname} "root" "anacrontab"
   done
fi
# User cron jobs
find /var/spool/cron -type f | while read dataline
do
   grep -v "^#" ${dataline} | while read crontabline
   do
         # allow for * * * * * file, and * * * * * sh -c "file"
         testvar=`echo "${crontabline}" | grep "\-c"`
         if [ "${testvar}." = "." ];
         then
            fname=`echo "${crontabline}" | awk {'print $6'}`
         else
            fname=`echo "${crontabline}" | awk {'print $8'}`
         fi
         crontabowner=`basename ${dataline}`
         find_file_perm PERM_CRON_JOB_FILE ${fname} "${crontabowner}" "crontab"
   done
done

# ======================================================================
# Collect basic network info to be checked
# ======================================================================

record_file HOSTS_ALLOW /etc/hosts.allow
record_file HOSTS_DENY /etc/hosts.deny
# --- Any equiv files on the server ? ---
if [ -f /etc/hosts.equiv ];
then
   find_file_perm PERM_HOSTS_EQIV_SYSTEM "/etc/hosts.equiv" "root"
   record_file HOSTS_EQIV /etc/hosts.equiv
fi
if [ -f /etc/ssh/shosts.equiv ];
then
   find_file_perm PERM_HOSTS_EQIV_SYSTEM "/etc/ssh/shosts.equiv" "root"
   record_file HOSTS_EQIV /etc/ssh/shosts.equiv
fi
find / -name ".rhosts" | while read dataline
do
   find_file_perm PERM_HOSTS_EQIV_USER "${dataline}" "NA"
   record_file HOSTS_EQIV ${dataline}
done
find / -name ".shosts" | while read dataline
do
   find_file_perm PERM_HOSTS_EQIV_USER "${dataline}" "NA"
   record_file HOSTS_EQIV ${dataline}
done

# --- How about any file shares ? ---
if [ -f /etc/exports ];
then
   find_file_perm PERM_ETC_EXPORTS "/etc/exports" "root"
   record_file ETC_EXPORTS_DATA /etc/exports
   cat /etc/exports | while read dataline
   do
       dirtocheck=`echo "${dataline}" | awk {'print $1'}`
       find_dir_perm PERM_EXPORTED_DIR ${dirtocheck} "root"
   done
fi

# --- what ports are being listened to ? ---
netstat -an | grep LISTEN | grep "tcp "| grep -v "::" | while read dataline
do
   echo "PORT_TCP_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep LISTEN | grep "tcp6 "| grep "::" | while read dataline
do
   echo "PORT_TCPV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep "udp "| grep -v "::" | while read dataline
do
   echo "PORT_UDP_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep "udp6 "| grep "::" | while read dataline
do
   echo "PORT_UDPV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep LISTEN | grep "unix "| while read dataline
do
   echo "PORT_UNIX_LISTENING=${dataline}" >> ${LOGFILE}
done

# Whats in the services file
record_file SERVICES_FILE /etc/services

# A few checks to see if samba is running
sambaRunning="NO"
testvar=`ps -ef | grep " smbd " | grep -v grep`
if [ "${testvar}." != "." ];
then
   sambaRunning="YES"
fi
testvar=`ps -ef | grep " nmbd " | grep -v grep`
if [ "${testvar}." != "." ];
then
   sambaRunning="YES"
fi
testvar=`netstat -an | grep LISTEN | grep ":139 "`
if [ "${testvar}." != "." ];
then
   sambaRunning="YES"
fi
echo "APPLICATION_SAMBA_RUNNING=${sambaRunning}" >> ${LOGFILE}

# ======================================================================
# motd should contain a auth/business notice.
# as should the sshd config, check root login flag here also
# ======================================================================
record_file MOTD_DATA /etc/motd
find_file_perm PERM_ETC_MOTD "/etc/motd" "root"
# MID: 2008/07/03 added sshd config and banner capture
if [ -f /etc/ssh/sshd_config ];
then
   record_file SSHD_CONFIG_DATA /etc/ssh/sshd_config
   xx=`grep -i "Banner" /etc/ssh/sshd_config | grep -v "^#"`
   if [ "${xx}." != "." ];
   then
      xx=`echo "${xx}" | awk {'print $2'}`
      if [ -f ${xx} ];
      then
         record_file SSHD_BANNER_DATA ${xx}
      fi
   fi
fi

# ======================================================================
# Files that must exist and be retained for a specific period (days)
# ======================================================================
require_file /var/log/auth.log 60 ".gz"
require_file /var/log/wtmp 60 ".gz"

# ======================================================================
#
#                          Config management.
#
# ======================================================================

# ======================================================================
# Collect all the files in /etc
# Note: at a later time we can use these files on the server that
# processes the extraction rather than having to collect so much
# ourselves in seperate steps above in this script.
# ======================================================================
if [ "${BACKUP_ETC}." == "yes." ];
then
   mydir=`pwd`
   cd /etc
   tar -cf ${ETCTARFILE} *
   cd ${mydir}
   echo "ETC_TARFILE=${ETCTARFILE}" >> ${LOGFILE}
else
   echo "ETC_TARFILE=" >> ${LOGFILE}
fi
# ======================================================================
# Also record what packages are installed.
# ======================================================================
if [ "${BACKUP_RPMLIST}." == "yes." ];
then
   rpm -qa > ${RPMFILE}
fi

# ======================================================================
# Collect the hardware profile for the server.
# ======================================================================
if [ -f ${HWFILE} ];
then
   /bin/rm ${HWFILE}
fi
if [ "${DO_HWLIST}." == "yes." ];
then
   # DMIDECODE will list all hardware details
   #   - number of memory slots, number used, max memory card size per slot
   #   - all IDE/ATA slots, and whether in use or free
   #   - all usb slots
   #   - all com/serial.ps2 ports 
   #   - etc
   if [ -x /usr/sbin/dmidecode ];
   then
       /usr/sbin/dmidecode >> ${HWFILE} 2>&1
   else
       cat << EOF >> ${HWFILE}
******************************************************************
/usr/sbin/dmidecode not found - Unable to list server hardware
profile for server ${myhost}.
******************************************************************
EOF
   fi
   # LSHW lists the actailly installed hardware
   # for example dmidecode will list that there are IDE slots in use,
   # but lshw will list the devices attached to those slots.
   # LSHW will not list spare slots, which is why we use the dmidecode
   # above also to get a full hardware profile.
   if [ -x /usr/sbin/lshw ];
   then
       /usr/sbin/lshw >> ${HWFILE} 2>&1
   else
       cat << EOF >> ${HWFILE}
******************************************************************
/usr/bin/lshw not found - Unable to list installed hardware for
server ${myhost}.
Use yum install lshw on server ${myhost} to resolve this.
******************************************************************
EOF
   fi
fi

# ======================================================================
timenow=`date`
echo "End time: ${timenow}"
