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
# 2020/02/xx - include 'raw' network ports listening as well as the
#              existing tcp/tcp6/udp/udp6 port recording (they exist
#              on my CentOS7 systems).
#              use fuser (if installed on the server) to collect info
#              on what process is using an open listening port or
#              unix socket file.
#              record all crontab lines we were unable to perform
#              command file permission checks against
#              suppress find and ls errors meaningless to users, so
#              running it is a little less cludgy looking
#              Now collect cron.allow and cron.deny info if those files
#              exist on the server.
#
# ======================================================================
MAX_SYSSCAN=""            # default is no limit parameter
SCANLEVEL_USED="FullScan" # default scanlevel status for collection file
BACKUP_ETC="yes"          # default is to tar up etc
BACKUP_RPMLIST="yes"      # default is to create a rpm package list
DO_HWLIST="yes"           # default is to create the hardware listing
DISABLE_FUSER="NO"        # default is to use fuser if installed on the server

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
                      if [ ${value} -lt 3 ];    # any less than 3 and it's not worth even reporting on
                      then
                         echo "*error* the --scanlevel value cannot be less than 3"
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
      "--disable-fuser") DISABLE_FUSER="YES"
                      ;;
      *)              echo "Unknown paramater value ${key}"
                      echo "Syntax:$0 [--scanlevel=<number>] [--backup-etc=yes|no] [--record-packages=yes|no] [--hwlist=yes|no] [--disable-fuser]"
                      echo "Please read the documentation."
                      exit 1
                      ;;
   esac
done

myrunner=`whoami`
if [ "${myrunner}." != "root." ];
then
   echo "This script can only be run by the root user."
   exit 1
fi

timenow=`date`
echo "Start time: ${timenow}"

# The filenames we need for output, erase if a rerun
LOGDIR=`pwd`
myhost=`hostname | awk -F. '{print $1'}`   # if hostname.xx.xx.com only want hostname
LOGFILE="${LOGDIR}/secaudit_${myhost}.txt"
ETCTARFILE="${LOGDIR}/etcfiles_${myhost}.tar"   # if we are backing up etc
HWFILE="${LOGDIR}/hwinfo_${myhost}.txt"
RPMFILE="${LOGDIR}/packagelist_${myhost}.txt"

# clean any files from any previous runs
if [ -f ${LOGFILE} ];
then
   /bin/rm -f ${LOGFILE}
fi
if [ -f ${ETCTARFILE} ];
then
   /bin/rm -f ${ETCTARFILE}
fi
if [ -f ${HWFILE} ];
then
   /bin/rm -f ${HWFILE}
fi
if [ -f ${RPMFILE} ];
then
   /bin/rm -f ${RPMFILE}
fi

# ======================================================================
#                           Helper tools
# ======================================================================
# ----------------------------------------------------------------------
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# output ls -la of dir + NA as expected owner
# Notes, added extra = to output as some filenames having spaces
# in the name threw out the data processing. The processing now
# expects and handles the second =.
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# ----------------------------------------------------------------------
find_perms_under_system_dir() {
   key="$1"
   startdir="$2"
   find_perms_under_dir "${key}" "${startdir}" "SYSTEM"
} # find_perms_under_system_dir

# ----------------------------------------------------------------------
# output ls -la of dir + expected-owner
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
#                  find_file_perm_nolog
# Find the permissions of a file. If the filename passed is a
# directory recurse down files under the directory.
# output ls -la of file + expected-owner
# DO NOT ECHO ANY OUTPUT TO THE USER, the only output to be echoed
# is a result value to the caller.
# ----------------------------------------------------------------------
find_file_perm_nolog() {
   key="$1"
   fname="$2"
   expected_owner="$3"
   optdata="$4"
   resultdata=""
   if [ -d ${fname} ];
   then
      find ${fname} 2>/dev/null | while read fname2
      do
         # Important, the find also returns the directory name we have just
         # asked for a find on, and endless loop if we recurs on that so check
         # for it (yes, linux allows find <dir>/* which stops that, but I want
         # to make this portable to non-linux also at some point).
         if [ "${fname2}." != "${fname}." ];   # do not recurse the directory name we are finding on yet again (loop time)
         then
            resultdata=`find_file_perm_nolog "${key}" "${fname2}" "${expected_owner}" "${optdata}"`
         fi
      done
   else
      tempvar=`ls -la ${fname} 2>/dev/null`
      # Added for cron jobs, the filename passed from those
      # data collections may not be a full path name but
      # could be using the search path, so try to locate it
      # if the 'ls' return code was not 0
      testresult=$?
      if [ ${testresult} -gt 0  ]
      then
         fname2=`which ${fname}`
         if [ "${fname2}." != "." ];
         then
            tempvar=`ls -la ${fname2}`
         fi
      fi
      # Replace any = in the filename with -, we use = as a delimiter
      tempvar=`echo "${tempvar}" | tr "\=" "-"`
      if [ "${tempvar}." != "." ];
      then
         resultdata="${key}=${tempvar}=${expected_owner} ${optdata}"
      fi
   fi
   echo "${resultdata}"
} # find_file_perm_nolog

# ----------------------------------------------------------------------
# Find the permissions of a file. If the filename passed is a
# directory recurse down files under the directory.
# output ls -la of file + expected-owner
# ----------------------------------------------------------------------
find_file_perm() {
   key="$1"
   fname="$2"
   expected_owner="$3"
   optdata="$4"

   resultdata=`find_file_perm_nolog "${key}" "${fname}" "${expected_owner}" "${optdata}"`
   if [ "${resultdata}." != "." ];
   then
      echo "${resultdata}" >> ${LOGFILE}
   else
      echo "*WARN* Error locating ${fname} for file permission check, skipped"
   fi
} # find_file_perm

# ----------------------------------------------------------------------
# Ensure at least $2 days of data is recorded in the filename
# provided. It is acceptable for the data to be retained in
# archived files managed by a log roller process, but in that
# case we can only go by the last modified date of the log
# archive itself in determining age.
# ----------------------------------------------------------------------
require_file() {
   fname="$1"
   days_needed="$2"
   archive_suffix="$3"
   ls -la ${fname} 2>/dev/null | while read dataline
   do
       echo "REQD_FILE=${days_needed};${dataline}" >> ${LOGFILE}
   done
   ls -la ${fname}*${archive_suffix} 2>/dev/null | while read dataline
   do
       echo "REQD_FILE=${days_needed};${dataline}" >> ${LOGFILE}
   done
} # require_file

# ----------------------------------------------------------------------
#                  get_process_by_exact_pid
# ----------------------------------------------------------------------
get_process_by_exact_pid() {
   pid="$1"
   if [ "${pid}." != "." ];
   then
      ps -ef | grep "${pid}" | grep -v "grep" | while read yy
      do
         # pid is field 2, only return the exact match
         exact=`echo "${yy}" | awk {'print $2'}`
         if [ "${exact}." == "${pid}." ];
         then
            programname=`echo "${yy}" | awk {'print $8" "$9" "$10" "$11'}`
            echo "${programname}"
         fi
      done
   else
      echo "No pid provided to search on"
   fi
} # end of get_process_by_exact_pid

# ----------------------------------------------------------------------
#                   get_fuser_network_process_exact
# called by identify_network_listening_processes to return the progam
# that has a tcp/tcp6/udp/udp6 port open and listening for connections.
# If multiple pids have the port open we only return the first.
#
# Note: reguardless of output format on RHEL
# based systems the pid list is written to stdout and all other
# information to stderr, so the pid list field starts at position 1
# always. This may not be the case on non RHEL systems.
#    [root@vmhost3 bin]# fuser -n tcp -v6 9090
#                         USER        PID ACCESS COMMAND
#    9090/tcp:            root          1 F.... systemd
#    [root@vmhost3 bin]# fuser -n tcp -v4 22
#                         USER        PID ACCESS COMMAND
#    22/tcp:              root      112022 F.... sshd
#    [root@vmhost3 bin]# fuser -n tcp  9090
#    9090/tcp:                1
# Also while we could 2>&1 and extract the command we can get a lot
# more detail from the ps output so we use that instead.
# ----------------------------------------------------------------------
get_fuser_network_process_exact() {
   # can be many pids on a port, only get info on the first
   # example fuser output below
   # [root@vmhost3 bin]# fuser -n tcp 44321
   # 44321/tcp:            1959
   # IMPORTANT: on RHEL based systems (Fedora/CentOS etc) the 44321/tcp: field
   #            is written to stderr and the pid list to stdout so we
   #            get the pid from postion 1 of stdout
   firstpid=`fuser $1 2>/dev/null | awk {'print $1'}`
   if [ "${firstpid}." != "." ];
   then
      programname=`get_process_by_exact_pid "${firstpid}"`
      echo "${programname}"
   else
      echo "fuser can find no process associated with this port"
   fi
} # end of get_fuser_network_process_exact

# ----------------------------------------------------------------------
#              get_fuser_socket_process_exact
# ----------------------------------------------------------------------
get_fuser_socket_process_exact() {
   sockname="$1"
   isreal=${sockname:0:1}
   if [ "${isreal}." == "/." ];
   then
      pidlist=`fuser ${sockname} 2>/dev/null`
      # most sockets have pid '1' as their owner, then additional pids
      pid2=""
      pid1=`echo "${pidlist}" | awk {'print $1'}`
      if [ "${pid1}." == "1." ];
      then
         pid2=`echo "${pidlist}" | awk {'print $2'}`
      fi
      if [ "${pid2}." != "." ];
      then
         programname=`get_process_by_exact_pid ${pid2}`
      else
         programname=`get_process_by_exact_pid ${pid1}`
      fi
      if [ "${programname}." != "." ];
      then
         echo "${programname}"
      else
         echo "fuser was unable to locate process"
      fi
   else
      echo "not queryable by fuser"
   fi
} # end of get_fuser_socket_process_exact

# ----------------------------------------------------------------------
#             identify_network_listening_processes
# ----------------------------------------------------------------------
identify_network_listening_processes() {
   # We can only collect this information if the "fuser" command is 
   # installed on the server.
   havefuser=`which fuser`
   if [ "${DISABLE_FUSER}." == "YES." ];
   then
      echo "FUSER_INSTALLED=DISABLED" >> ${LOGFILE}
   elif [ "${havefuser}." != "." ];
   then
      echo "FUSER_INSTALLED=YES" >> ${LOGFILE}
      netstat -an | while read xx
      do
         listenport=""
         listenprocess=""
         # handling for tcp listening ports
         testvar=`echo "${xx}" | grep "^tcp"`
         if [ "${testvar}." != "." ];
         then
            testvar=`echo "${xx}" | grep "^tcp6"`
            if [ "${testvar}." != "." ];
            then
               islistening=`echo "${xx}" | grep "LISTEN"`
               if [ "${islistening}." != "." ];
               then
                  listenaddr=`echo "${xx}" | awk '{print $4'}`
                  # the last field we know is the port, print the fieldcount field
                  listenport=`echo "${listenaddr}" | awk -F: '{print $NF}'`
                  listenprocess=`get_fuser_network_process_exact "-n tcp -6 ${listenport}"`
                  if [ "${listenprocess}." != "." ]
                  then
                     echo "NETWORK_TCPV6_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
                  fi
               fi
            else
               islistening=`echo "${xx}" | grep "LISTEN"`
               if [ "${islistening}." != "." ];
               then
                  listenaddr=`echo "${xx}" | awk {'print $4'}`
                  listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
                  listenprocess=`get_fuser_network_process_exact "-n tcp -4 ${listenport}"`
                  if [ "${listenprocess}." != "." ]
                  then
                     echo "NETWORK_TCPV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
                  fi
               fi
            fi   # if/else tcp5
         fi   # if tcp
         # handling for udp listening ports
         testvar=`echo "${xx}" | grep "^udp"`
         if [ "${testvar}." != "." ];
         then
            testvar=`echo "${xx}" | grep "^udp6"`
            if [ "${testvar}." != "." ];
            then
               # different number of : delimeters in addresses
               listenaddr=`echo "${xx}" | awk '{print $4'}`
               # the last field we know is the port, print the fieldcount field
               listenport=`echo "${listenaddr}" | awk -F: {'print $NF'}`
               listenprocess=`get_fuser_network_process_exact "-n udp -6 ${listenport}"`
               if [ "${listenprocess}." != "." ]
               then
                  echo "NETWORK_UDPV6_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
               fi
            else
               listenaddr=`echo "${xx}" | awk {'print $4'}`
               listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
               listenprocess=`get_fuser_network_process_exact "-n udp -4 ${listenport}"`
               if [ "${listenprocess}." != "." ]
               then
                  echo "NETWORK_UDPV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
               fi
            fi
         fi
         # fuser does not return info on ports listening on 'raw' sockets
         testvar=`echo "${xx}" | grep "^raw"`
         if [ "${testvar}." != "." ];
         then
            listenaddr=`echo "${xx}" | awk {'print $4'}`
            listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
            echo "NETWORK_RAW_PORT_${listenport}=fuser cannot return info on raw sockets" >> ${LOGFILE}
         fi
         # identify processes listening on sockets if possible
         testvar=`echo "${xx}" | grep "^unix"`
         if [ "${testvar}." != "." ];
         then
            islistening=`echo "${xx}" | grep "LISTEN"`
            if [ "${islistening}." != "." ];
            then
               socketname=`echo "${xx}" | awk {'print $9'}`
               listenprocess=`get_fuser_socket_process_exact "${socketname}"`
               echo "NETWORK_UNIX_SOCKET=${socketname}:${listenprocess}" >> ${LOGFILE}
            fi
         fi
      done
   else
      echo "FUSER_INSTALLED=NO" >> ${LOGFILE}
      echo "**warning** as 'fuser' is not installed on this server information is not"
      echo ".           being collected for processes listening on network ports."
   fi  # if we have a fuser commmand
} # end of identify_network_listening_processes

# MAINLINE STARTS
# ======================================================================
# Record the server details
# ======================================================================
myhost=`hostname`
mydate=`date +"%Y/%m/%d %H:%M"`
osversion=`uname -r`
ostype=`uname -s`
echo "TITLE_HOSTNAME=${myhost}" >> ${LOGFILE}
echo "TITLE_CAPTUREDATE=${mydate}" >> ${LOGFILE}
echo "TITLE_OSVERSION=${osversion}" >> ${LOGFILE}
echo "TITLE_OSTYPE=${ostype}" >> ${LOGFILE}
echo "TITLE_FileScanLevel=${SCANLEVEL_USED}" >> ${LOGFILE}
echo "TITLE_ExtractVersion=0.06" >> ${LOGFILE}

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
#                       from /, so specify all the system file directories.
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
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null | while read dataline
do
   echo "SUID_FILE=${dataline}" >> ${LOGFILE}
done
find / -type f -perm -2000 -exec ls -la {} \; 2>/dev/null | while read dataline
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
# Are cron.allow and cron.deny being used ?
# ======================================================================
if [ -f /etc/cron.deny ];
then
   echo "CRON_DENY_EXISTS=YES" >> ${LOGFILE}
   cat /etc/cron.deny | while read dataline
   do
      echo "CRON_DENY_DATA=${dataline}" >> ${LOGFILE}
   done
else
   echo "CRON_DENY_EXISTS=NO" >> ${LOGFILE}
fi
if [ -f /etc/cron.allow ];
then
   echo "CRON_ALLOW_EXISTS=YES" >> ${LOGFILE}
   cat /etc/cron.allow | while read dataline
   do
      echo "CRON_ALLOW_DATA=${dataline}" >> ${LOGFILE}
   done
else
   echo "CRON_ALLOW_EXISTS=NO" >> ${LOGFILE}
fi

# ======================================================================
# Collect permissions of jobs run by cron
# ======================================================================
# User cron jobs
find /var/spool/cron -type f 2>/dev/null | while read dataline
do
   # record each crontab filename, we check those in processing also
   filenamedata=`basename ${dataline}`
   echo "CRON_SPOOL_CRONTAB_FILE=${filenamedata}" >> ${LOGFILE}
   # then record the contents of each crontab
   crontabowner=`basename ${dataline}`
   # exclude commands and common environment variable settings that may be in crontabs before schedules
   grep -v "^#" ${dataline} | grep -v "^PATH=" | grep -v "^SHELL=" | while read crontabline
   do
      if [ ${#crontabline} -gt 10 ]; # try and ignore blank lines
      then
         # allow for * * * * * file, and * * * * * sh -c "file"
         testvar=`echo "${crontabline}" | grep "\-c"`
         if [ "${testvar}." = "." ];
         then
            fname=`echo "${crontabline}" | awk {'print $6'}`
         else
            fname=`echo "${crontabline}" | awk {'print $8'}`
            # if command after "shell -c" is in quotes remove the start/end quotes
            aa=${fname:0:1}
            if [ "${aa}." == "\"." -o "${aa}." == "\'." ];
            then
               fname=${fname:1:${#fname}}
               # may not have a tailing quote if there was a space after the command,
               # so test before  removing the last char.
               aa=${fname:$(( ${#fname} - 1 )):1}
               if [ "${aa}." == "\"." -o "${aa}." == "\'." ];
               then
                  fname=${fname:0:$((${#fname} - 1))}
               fi
            fi
         fi
         resultdata=`find_file_perm_nolog PERM_CRON_JOB_FILE ${fname} "${crontabowner}" "crontab"`
         if [ "${resultdata}." != "." ];
         then
            echo "${resultdata}@${crontabline}" >> ${LOGFILE}
         else # record crontab lines we could not check file perms for
              # these will be lines with commands such as 'cd xxx;./command'
            echo "NO_PERM_CRON_JOB_FILE=${crontabowner} crontab:@${crontabline}" >> ${LOGFILE}
         fi
      fi
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
find / -name ".rhosts" 2>/dev/null | while read dataline
do
   find_file_perm PERM_HOSTS_EQIV_USER "${dataline}" "NA"
   record_file HOSTS_EQIV ${dataline}
done
find / -name ".shosts" 2>/dev/null | while read dataline
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
netstat -an | grep LISTEN | grep "^tcp "| grep -v "::" | while read dataline
do
   echo "PORT_TCP_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep LISTEN | grep "^tcp6 "| grep "::" | while read dataline
do
   echo "PORT_TCPV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep "^udp "| grep -v "::" | while read dataline
do
   echo "PORT_UDP_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep "^udp6 "| grep "::" | while read dataline
do
   echo "PORT_UDPV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep "^raw"| grep "::" | while read dataline
do
   echo "PORT_RAW_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an | grep LISTEN | grep "unix "| while read dataline
do
   echo "PORT_UNIX_LISTENING=${dataline}" >> ${LOGFILE}
done

# try to match a running process to any listening network port
identify_network_listening_processes

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
# Depending on processing options some files may not have been produced
# so only list those that were.
echo "Copy the below files to the reporting server to be processed."
echo "${LOGFILE}"
if [ -f ${ETCTARFILE} ];
then
   echo "${ETCTARFILE}"
fi
if [ -f ${HWFILE} ];
then
   echo "${HWFILE}"
fi
if [ -f ${RPMFILE} ];
then
   echo "${RPMFILE}"
fi

# ======================================================================
timenow=`date`
echo "End time: ${timenow}"
