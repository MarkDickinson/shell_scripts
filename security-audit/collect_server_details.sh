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
#            --scanlevel=N                   default is unlimited full scan
#            --backup-etc=yes|no             default is no
#            --record-packages=yes|no        default is no
#            --hwlist=yes|no                 default is yes
#            --webpathlist=/some/filename    default is no special web path processing
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
# 2020/02/29 - include 'raw' network ports listening as well as the
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
# 2020/03/06 - remove requirement for fuser, now use the pid from    
#              netstat and the ps command to find what process is
#              listening on a port (fuser could not query all ports
#              (ie: it doesn't support raw ports, and failed to return
#              info on some udp ports).
# 2020/03/22 - changed parm handling to not abort on the first error
#              but to report on all bad parms beofre aborting.
#              added capture for --webpathlist processing.
#              when capturing the system file list now exclude links, as
#              we still capture the files they point at we don't want links
#              capture all iptables accept rules
#              as well as recording capture date in text, save seconds since
#              epoc also so we can use it for simple tests is a file has
#              been updated in the processing script.
# 2020/05/28 - changed defaults for backing up /etc and creating a rpm
#              package list from yes to no, as I do not use that collected
#              info anywhere yet.
# 2020/06/23 - Bugfix: changed grep -v "\-c" in crontab file permission
#              checks to grep -v "\ \-c\ " do it only matches if spaces
#              on either side if the -c parm in commands such as
#              'sh -c command', as it was hitting files with -c in the
#              command filename which was not intended. Also test only
#              on first few fields of the crontab command to try to
#              avoid matching on any commands that also use -c.
#              New: now collect a full 'ps -ef' list that the processing
#              script can use.
#              F23/CentOS8/RHEL8 onwards that run firewalld use netfilter
#              rules as a backend instead of iptables, so we now try
#              and collect netfilter rules if nft is installed as well.
#
# ======================================================================
EXTRACT_VERSION="0.10"    # used to sync between capture and processing, so be correct
MAX_SYSSCAN=""            # default is no limit parameter
SCANLEVEL_USED="FullScan" # default scanlevel status for collection file
BACKUP_ETC="no"           # default is NOT to tar up etc
BACKUP_RPMLIST="no"       # default is NOT to create a rpm package list
DO_HWLIST="yes"           # default is to create the hardware listing
WEBPATHFILE=""            # default is no file of special webserver directories
WEBPATHEXCLUDE=""         # only set if above parm is used

PARM_ERRORS="no"
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
                         PARM_ERRORS="yes"
                      fi
                      if [ ${value} -lt 3 ];    # any less than 3 and it's not worth even reporting on
                      then
                         echo "*error* the --scanlevel value cannot be less than 3"
                         PARM_ERRORS="yes"
                      fi
                      SCANLEVEL_USED="${value}"
                      MAX_SYSSCAN="-maxdepth ${value}"
                      shift
                      ;;
      "--backup-etc") if [ "${value}." != "yes." -a "${value}." != "no." ];
                      then
                         echo "*error* the --backup-etc value provided is not yes or no"
                         PARM_ERRORS="yes"
                      fi
                      BACKUP_ETC="${value}"
                      shift
                      ;;
      "--record-packages") if [ "${value}." != "yes." -a "${value}." != "no." ];
                      then
                         echo "*error* the --record-packages value provided is not yes or no"
                         PARM_ERRORS="yes"
                      fi
                      DO_HWLIST="${value}"
                      shift
                      ;;
      "--hwlist")     if [ "${value}." != "yes." -a "${value}." != "no." ];
                      then
                         echo "*error* the --hwlist value provided is not yes or no"
                         PARM_ERRORS="yes"
                      fi
                      DO_HWLIST="${value}"
                      shift
                      ;;
      "--webpathlist") if [ ! -f ${value} ];
                      then
                         echo "*error* the filename specified by the --webpathlist parameter does not exist"
                         PARM_ERRORS="yes"
                      else
                         WEBPATHFILE="${value}"
                      fi
                      shift
                      ;;
      *)              echo "*error* the parameter ${key} is not a valid parameter"
                      PARM_ERRORS="yes"
                      shift
                      ;;
   esac
done
if [ "${WEBPATHFILE}." != "." ];
then
    datacount=`cat ${WEBPATHFILE} | grep -v "^#" | wc -l`
    if [ ${datacount} -lt 1 ];
    then
       echo "*error* the file specified with the --webpathlist option is empty"
       PARM_ERRORS="yes"
    else
       # a lot of messing about, yes we do need to use a file as this is another
       # case where variables altered inside a do loop are isolated, and their changes
       # lost as soon as the 'done' is hit, so we need to store the changes in a file
       # so we can retrieve the changes after the done.
       tmpname=`basename $0`
       tmpname="/var/tmp/${tmpname}.wrk"
       # to insert "\( -path dir1 -o -path dir2 -o -path dir3 \) -prune -o print" into the system directory search
       # routine to exclude the directories identified as being web directories needing seperate checking.
       cat ${WEBPATHFILE} | grep -v "^#" | while read fpath
       do
          if [ "${fpath}." != "." ];   # skip blank lines
          then
             WEBPATHEXCLUDE="${WEBPATHEXCLUDE} -path ${fpath} -o"
             echo "${WEBPATHEXCLUDE}" > ${tmpname}
          fi
       done
       # drop the extra -o we have on the end
       WEBPATHEXCLUDE=`cat ${tmpname}`
       len1=${#WEBPATHEXCLUDE}
       len2=$((${len1} - 3))
       WEBPATHEXCLUDE=${WEBPATHEXCLUDE:0:${len2}}
       WEBPATHEXCLUDE="( ${WEBPATHEXCLUDE} ) -prune -o -print"
    fi
fi
if [ "${PARM_ERRORS}." != "no." ];
then
   echo "Data capture aborted due to the above errors"
   echo "Syntax:$0 [--scanlevel=<number>] [--backup-etc=yes|no] [--record-packages=yes|no] [--hwlist=yes|no] [--webpathlist=/some/filename]"
   echo "Please read the documentation."
   exit 1
fi

myrunner=`whoami`
if [ "${myrunner}." != "root." ];
then
   echo "This script can only be run by the root user !."
   echo "Much of the information being colected is not available to anyone but the root user."
   exit 1
fi

echo "$0 collector version is ${EXTRACT_VERSION}"
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
# Added so I can see what tasks are taking the longest time so I can
# tune those collection functions later.
# ----------------------------------------------------------------------
timestamp_action() {
   msgtext="$1"
   tstamp=`date`
   echo "${tstamp} : ${msgtext}"
} # end of timestamp_action

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
   if [ "${expected_owner}." == "." ];
   then
      expected_owner="NA"  # can be any owner
   fi
# ----- when using the webpathexclude we get a lot of files not normally detected ----
#       leave the var in for now, as I explicitly reset it to empty while working on the issue
# do not capture symbolic links (grep -v the perms), the files they point to will be captured
   find -P ${startdir} ${MAX_SYSSCAN} -mount -type f ${WEBPATHEXCLUDE} -exec ls -la {} \; | grep -v "^lrwxrwxrwx" | grep -v "\/tmp\/" | tr "\=" "-" | while read dataline
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
      grep "${pid}" identify_network_listening_processes.wrk | while read yy
      do
         # pid is field 2, only return the exact match
         exact=`echo "${yy}" | awk {'print $2'}`
         if [ "${exact}." == "${pid}." ];
         then
            programname=`echo "${yy}" | awk {'print $8" "$9" "$10" "$11" "$12" "$13" "$14" "$15'}`
            programname=`echo "${programname}"`     # remove traing spaces we may have inserted
            echo "${programname}"
         fi
      done
   else
      echo "No pid provided to search on"
   fi
} # end of get_process_by_exact_pid

# ----------------------------------------------------------------------
#             identify_network_listening_processes
# ----------------------------------------------------------------------
identify_network_listening_processes() {
   # put ps into a workfile to avoid running it many times
   ps -ef > identify_network_listening_processes.wrk
   netstat -an -p | while read xx
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
               # get the pid from the netstat value
               pid=`echo "${xx}" | awk {'print $7'} | awk -F\/ {'print $1'}`
               listenprocess=`get_process_by_exact_pid "${pid}"`
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
               # get the pid from the netstat value
               pid=`echo "${xx}" | awk {'print $7'} | awk -F\/ {'print $1'}`
               listenprocess=`get_process_by_exact_pid "${pid}"`
               if [ "${listenprocess}." != "." ]
               then
                  echo "NETWORK_TCPV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
               fi
            fi
         fi   # if/else tcp6
      fi   # if tcp
      # handling for udp ports (they do not LISTEN and are always active)
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
            # get the pid from the netstat value
            pid=`echo "${xx}" | awk {'print $6'} | awk -F\/ {'print $1'}`
            listenprocess=`get_process_by_exact_pid "${pid}"`
            if [ "${listenprocess}." != "." ]
            then
               echo "NETWORK_UDPV6_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
            fi
         else
            listenaddr=`echo "${xx}" | awk {'print $4'}`
            listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
            # get the pid from the netstat value
            pid=`echo "${xx}" | awk {'print $6'} | awk -F\/ {'print $1'}`
            listenprocess=`get_process_by_exact_pid "${pid}"`
            if [ "${listenprocess}." != "." ]
            then
               echo "NETWORK_UDPV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
            fi
         fi
      fi
      testvar=`echo "${xx}" | grep "^raw"`
      if [ "${testvar}." != "." ];
      then
         testvar=`echo "${xx}" | grep "^raw6"`
         if [ "${testvar}." == "." ];     # not raw6, so raw4
         then
            listenaddr=`echo "${xx}" | awk {'print $4'}`
            listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
            # get the pid from the netstat value
            pid=`echo "${xx}" | awk {'print $7'} | awk -F\/ {'print $1'}`
            listenprocess=`get_process_by_exact_pid "${pid}"`
            if [ "${listenprocess}." != "." ]
            then
               echo "NETWORK_RAWV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
            fi
         else   # is raw6
            # different number of : delimeters in addresses
            listenaddr=`echo "${xx}" | awk '{print $4'}`
            # the last field we know is the port, print the fieldcount field
            listenport=`echo "${listenaddr}" | awk -F: {'print $NF'}`
            # get the pid from the netstat value
            pid=`echo "${xx}" | awk {'print $7'} | awk -F\/ {'print $1'}`
            listenprocess=`get_process_by_exact_pid "${pid}"`
            if [ "${listenprocess}." != "." ]
            then
               echo "NETWORK_RAWV6_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
            fi
         fi
      fi
      # identify processes listening on sockets if possible
      testvar=`echo "${xx}" | grep "^unix"`
      if [ "${testvar}." != "." ];
      then
         checktype=`echo "${xx}" | egrep -h "STREAM|SEQPACKET"`
         if [ "${checktype}." != "." ];
         then
            socketname=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $5'}`
            inode=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $3'}`
            # get the pid from the netstat value
            pid=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $4'} | awk -F\/ {'print $1'}`
            # some 'stream' entries do not have a state field so all parms are back one
            if [ "${pid}." == "." ];
            then
               socketname=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $4'}`
               inode=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $2'}`
               pid=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $3'} | awk -F\/ {'print $1'}`
            fi
            listenprocess=`get_process_by_exact_pid "${pid}"`
            if [ "${listenprocess}." != "." ]
            then
               echo "NETWORK_UNIX_STREAM=${inode}:${socketname}=${listenprocess}" >> ${LOGFILE}
            fi
         else
            checktype=`echo "${xx}" | grep "DGRAM"`
            if [ "${checktype}." != "." ];
            then
               socketname=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $4'}`
               inode=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $2'}`
               # get the pid from the netstat value
               pid=`echo "${xx}" | awk -F\] {'print $2'} | awk {'print $3'} | awk -F\/ {'print $1'}`
               listenprocess=`get_process_by_exact_pid "${pid}"`
               if [ "${listenprocess}." != "." ]
               then
                  echo "NETWORK_UNIX_DGRAM=${inode}:${socketname}=${listenprocess}" >> ${LOGFILE}
               fi
            fi
         fi
      fi
   done
   /bin/rm identify_network_listening_processes.wrk
} # end of identify_network_listening_processes

# MAINLINE STARTS
# ======================================================================
# Record the server details
# ======================================================================
myhost=`hostname`
mydate=`date +"%Y/%m/%d %H:%M"`
mydate2=`date +"%s"`
osversion=`uname -r`
ostype=`uname -s`
echo "TITLE_HOSTNAME=${myhost}" >> ${LOGFILE}
echo "TITLE_CAPTUREDATE=${mydate}" >> ${LOGFILE}
echo "TITLE_OSVERSION=${osversion}" >> ${LOGFILE}
echo "TITLE_OSTYPE=${ostype}" >> ${LOGFILE}
echo "TITLE_FileScanLevel=${SCANLEVEL_USED}" >> ${LOGFILE}
echo "TITLE_ExtractVersion=${EXTRACT_VERSION}" >> ${LOGFILE}
# not TITLE_ as averything title_ is used in server header listings
echo "DATA_CAPTURE_EPOC_SECONDS=${mydate2}" >> ${LOGFILE}

# ======================================================================
# Collect User Details and key system defaults.
# ======================================================================
timestamp_action "collecting security config files"
record_file PASSWD_FILE /etc/passwd           # user details
record_file PASSWD_SHADOW_FILE /etc/shadow    # password and expiry details
record_file ETC_GROUP_FILE /etc/group         # the user groups on the server
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
#if [ "${WEBPATHFILE}." != "." ];
#then
#   timestamp_action "collecting system file details (excluding specified webserver directories)"
#else
   timestamp_action "collecting system file details"
#fi
WEBPATHEXCLUDE=""            # DEBUG- removed as it results in multiple entries per file for some reason
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
#
# If we excluded directories in the above prcessing as they were
# defined as webpath directories we must capture them now.
WEBPATHEXCLUDE=""            # always reset this anyway, not needed anymore
if [ "${WEBPATHFILE}." != "." ];
then
   timestamp_action "collecting specified webserver file details"
   savescan="${MAX_SYSSCAN}" # webserver path scans are always a full scan
   MAX_SYSSCAN=""            # so clear the maxdepth the user set
   cat ${WEBPATHFILE} | grep -v "^#" | while read webpath
   do
      find_perms_under_dir "PERM_WEBSERVER_FILE" "${webpath}" "WEBUSER"
   done
   MAX_SYSSCAN="${savescan}" # and back to user defined scan level
fi

# ======================================================================
# Collect perms of user directories.
# ======================================================================
timestamp_action "collecting user home directory information"
cat /etc/passwd | while read dataline
do
   userdetails=`echo "${dataline}" | awk -F: {'print $6" "$1'}` # dir and user
   find_dir_perm "PERM_HOME_DIR" ${userdetails}   # pass dir and user with key
done

# ======================================================================
# Find all SUID fileser directories.
# From F20 (19?) -perm +6000 is not permitted to find both,
# we have to seperately search on -4000 and -2000 now
# ======================================================================
timestamp_action "collecting suid file details"
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
timestamp_action "collecting cron information"
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
         testvar=`echo "${crontabline}" | awk {'print $6" "$7" "$8'}`
         testvar=`echo "${testvar}" | grep "\ \-c\ "`
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
timestamp_action "collecting information on open network ports and sockets"

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
netstat -an -p | grep LISTEN | grep "^tcp "| grep -v "::" | while read dataline
do
   echo "PORT_TCPV4_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an -p | grep LISTEN | grep "^tcp6 "| grep "::" | while read dataline
do
   echo "PORT_TCPV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an -p | grep "^udp "| grep -v "::" | while read dataline
do
   echo "PORT_UDPV4_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an -p | grep "^udp6 "| grep "::" | while read dataline
do
   echo "PORT_UDPV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an -p | grep "^raw"| grep -v "::" | while read dataline
do
   echo "PORT_RAWV4_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an -p | grep "^raw6"| while read dataline
do
   echo "PORT_RAWV6_LISTENING=${dataline}" >> ${LOGFILE}
done
netstat -an -p | grep "^unix" | while read dataline
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

# iptables ACCEPT rules
haveiptables=`which iptables`
if [ "${haveiptables}." != "." ];
then
   timestamp_action "collecting firewall rules from iptables"
   iptables -n -v -L | while read dataline
   do
      echo "IPTABLES_FULLDATA=${dataline}" >> ${LOGFILE}
   done
else
   timestamp_action "**warning** iptables command not installed, cannot collect firewall rules using iptables"
fi
# F32/CentOS8/RHEL8 if using firewalld now use nftables instead of iptables
havenft=`which nft`
if [ "${havenft}." != "." ];
then
   timestamp_action "collecting firewall rules from netfilter"
   nft list ruleset | while read dataline
   do
      echo "NFTABLES_FULLDATA=${dataline}" >> ${LOGFILE}
   done
# else no issue, netfilter is not on servers prior to F23/C8/RH8 by default
fi

# ======================================================================
# motd should contain a auth/business notice.
# as should the sshd config, check root login flag here also
# ======================================================================
timestamp_action "collecting motd and ssh-banner information"
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
timestamp_action "collecting info on files that must be retained"
require_file /var/log/auth.log 60 ".gz"
require_file /var/log/wtmp 60 ".gz"

# ======================================================================
# Record all processes that are running at the time the snapshot ran.
# ======================================================================
timestamp_action "recording running process list"
ps -ef | while read dataline
do
   echo "PROCESS_RUNNING=${dataline}" >> ${LOGFILE}
done

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
   timestamp_action "performing tar of /etc"
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
   timestamp_action "saving the installed packages information"
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
   timestamp_action "collecting hardware information"
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
