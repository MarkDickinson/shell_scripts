#!/usr/bin/env bash
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
# 2020/06/27 - Added /usr/sbin to the PATH as when running this script
#              from cron it was unable to find files under /usr/sbin
# 2020/07/05 - Added >2/dev/null to the which iptables and which nft  
#              checks as when nft was not installed on the server (C7)
#              the not found error was written to the output (cosmetic change)
# 2020/07/06 - Altered version from 0.10 to 0.11 to match the processing
#              script version change.
# 2020/08/18 - Updates for version 0.12
#              Record if NetworkManager is running on the server. Only
#              if it is will the processing of networkmanager_downgrade
#              firewall ports be permitted.
#              Collect wtmp information using 'last -i', tagged LAST_LOG,
#              need the -i option to capture ipaddr info I will use
#              in later planned enhancements in addition to the checks
#              to be done on checking user logins
#              Use 'ip a' to collect network interface info, I need this 
#              in later planned enhancements
#              Find orphaned (no user in /etc/passwd matching uid number)
#              directories and files, I need this in later planned
#              processing.
# 2020/09/01 - Updates for version 0.13
#              Collect info on at.allow and at.deny files.
#              Collect minlen setting from pwquality.conf if uncommented
#              in that file; as it overrides the value in login.defs on
#              PAM systems so we need to collect it if present
#              Use lastlog to collect last logged on info to avoid
#              having to parse the fill last output
# 2020/09/10 - Updates for version 0.14
#              Collect selinux config information
# 2020/10/03 - Updates for version 0.15
#              now collect some user authorized_keys info
# 2020/11/10 - Updates for version 0.16
#              Collect sudoers information for additional AppendixL
# 2020/11/15 - Updates for version 0.17
#              Updated version number to match processing script version
#              which had a lot of changes made and was version bumped
# 2020/12/22 - Updates for version 0.18
#              Updated version number to match processing script version
#              which had a lot of changes made and was version bumped
#              Altered test of network port pid search that records
#              details of the process holding a port open to record
#              an unknown (kernel?) opener where netstat reports a
#              pid of '-' (or any non-numeric pid) rather than record
#              nothing as with no entry recorded the processing script
#              raises alerts as it expects an open port to have an entry.
# 2021/10/03 - Updates for version 0.19
#              BugFix for orphaned file collection.
#              Record any active bluetooth connections (a wireless card
#              on my laptop started reporting these after replacing
#              centos8 with rocky, and need to be audited.
#              Version bump to match processing script.
# 2021/12/27 - In /etc/sudoers Debian uses @includedir (rhel uses #includedir)
#              so includes were not being checked for debian, now that
#              is checked for also. No version bump as no extra functionality.
# 2022/06/04 - Version bump to match processing script version change
# 2023/11/24 - TITLE_OSKERNEL now used to store kernel version, the   
#              origional TITLE_OSVERSION is now instead used to store the
#              'pretty name' of the OS obtained from /etc/os-release
#              if it exists in that file. Version now 0.21 to match the
#              version bump in the processing script to cope with the change.
#              Also now record whats in hosts.allow and hosts.deny
# 2025/08/26 - Discovered when I hit enter too soon I was not checking for
#              an idiot like me using --scanlevel=[enter] instead of the
#              correct --scanlevel=number[enter] so added a check for that
#              input validation. Left version at 0.21 as just a minor fix
#              that affects nobody using it properly.
# 2025/08/30 - Now collect user .ssh/config and .ssh/rc files if they     
#              exist also so the processing script can check for entries
#              indicating commands are trigered on connection; and the
#              processing script will be updated to check for commands
#              being run on ssh connections by the global sshd_config also.
#              Also seperately collect dirperms on .ssh directories to check.
#              This is a version bump to 0.22
# 2025/12/10 + In progress. Starting to implement SunOS data collection.
#          (1) All 'which' commands now have a 'grep -v "no xxx in' as
#              SunOS does not redirect the error message to stderr
#          (2) SunOS does not support all the Linux 'find' flags, use
#              a variable and opts removed if SunOS
#          (3) No 'ip' command, use ifconfig for the interface dump
#              if SunOS
#              This is a TEST version bump to 0.22S BETA
# 2025/12/27 - Version bump to 0.23 as it has a bugfix   
#          (1) BugFix. In .ssh directory check was collecting the ..    
#              directory perms instead of the . so was reporting on
#              user homedir not .ssh dir perms 
#          (2) Added SunOS network listening port info collection,
#              capture /etc/default/password to use for SunOS checks
#              in the processing script id OSTYPE is SunOS (processing
#              script still uses login.defs/pwquality.conf if Linux)
#
# ======================================================================
# Added the below PATH as when run by cron no files under /usr/sbin were
# being found (like iptables and nft).
export PATH=$PATH:/usr/sbin

EXTRACT_VERSION="0.23"    # capture script version
MAX_SYSSCAN=""            # default is no limit parameter
SCANLEVEL_USED="FullScan" # default scanlevel status for collection file
BACKUP_ETC="no"           # default is NOT to tar up etc
BACKUP_RPMLIST="no"       # default is NOT to create a rpm package list
DO_HWLIST="yes"           # default is to create the hardware listing
WEBPATHFILE=""            # default is no file of special webserver directories
WEBPATHEXCLUDE=""         # only set if above parm is used
WORKDIR=`pwd`             # where to store temporary files

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
		      if [ "${value}." == "." ];    # check for no value provided at all --scanlevel=[enter], yes I oopsied that
		      then
                         echo "*error* the --scanlevel value cannot be blank"
                         PARM_ERRORS="yes"
			 value=3      # so the below check does not error with no value in the number
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
                      BACKUP_RPMLIST="${value}"
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
   echo "Much of the information being collected is not available to anyone but the root user."
   exit 1
fi

OStypeName=`uname -s`
if [ "${OStypeName}." == "Linux." ];
then
	LinuxFindOpts="-P -H"
else
	LinuxFindOpts="-H"   # -P not available on SunOS
fi


echo "$0 collector script version is ${EXTRACT_VERSION}"
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
# Some lists we need in multiple places
# ======================================================================
# System directories to search for
#   * badly secured system files
#   * orphaned files
if [ -d /sys ];  # SunOS does not have /sys
then
   SYSTEM_DIR_LIST="/bin /boot /dev /etc /lib /opt /sbin /sys /usr /var"
else
   SYSTEM_DIR_LIST="/bin /boot /dev /etc /lib /opt /sbin /usr /var"
fi
# All filesystems to search fo
#   * directories to search for orphaned files in
ALL_DIR_LIST="${SYSTEM_DIR_LIST} /home"

# A list of filenames for special handling within cron job file checks
CRON_CMD_IGNORE_LIST="/usr/bin/echo /bin/echo /usr/bin/espeak"                       # commands to ignore as non-disruptive
CRON_CMD_SHELL_LIST="/usr/bin/php /usr/bin/bash /usr/bin/csh /usr/bin/sh /bin/sh sh" # commands we want the second field as...
                                                                                     #    ...the command being executed
CRON_CMD_FATAL_LIST="/usr/bin/cd /usr/bin/find /usr/bin/ls"                          # commands that will invalidate all checks

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
# Logs the entire contects of a file prefixed by the 'key'.
# The processing script will have to check for anything in the files.
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
   else
      echo "${key}=MISSING FILE ${file}" >> ${LOGFILE}
   fi
} # record_file

# ----------------------------------------------------------------------
# When passed a data 'list' will write out each item in the list as
# a seperate line, so the list can be easily used in while loops.
# ----------------------------------------------------------------------
extract_as_unique_lines() {
   while [[ $# -gt 0 ]];
   do
      echo "$1"
      shift
   done
} # end of extract_as_unique_lines

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
   find ${LinuxFindOpts} ${startdir} ${MAX_SYSSCAN} -mount -type f ${WEBPATHEXCLUDE} -exec ls -la {} \; | grep -v "^lrwxrwxrwx" | grep -v "\/tmp\/" | tr "\=" "-" | while read dataline
   do
      echo "${key}=${dataline}=${expected_owner}" >> ${LOGFILE}
   done
} # find_perms_under_dir

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
      # Instead, have to get dirname and basename parts and grep that way
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
   optdata="$4"    # Note: may be "NA" but must be passed as we check for unset variables now
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
         fname2=`which ${fname} | grep -v "no ${fname} in"`
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
            programname=`echo ${programname}`    # remove leading/trailing spaces we may have inserted
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
            else
               echo "NETWORK_UDPV6_PORT_${listenport}=(no pid available for pid \"${pid}\", kernel?)" >> ${LOGFILE}
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
            else
               echo "NETWORK_UDPV4_PORT_${listenport}=(no pid available for pid \"${pid}\", kernel?)" >> ${LOGFILE}
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
      # 0.19 capture bluetooth connections also (a Rocky laptop with a wireless card started showing these)
      testvar=`echo "${xx}" | egrep "^l2cap|^rfcomm"`
      if [ "${testvar}." != "." ];
      then
         echo "ACTIVE_BLUETOOTH_CONNECTION=${xx}" >> ${LOGFILE}
      fi
   done
   /bin/rm identify_network_listening_processes.wrk
} # end of identify_network_listening_processes

# ----------------------------------------------------------------------
#             identify_network_listening_processes_sunos
# Of course SunOS outputs in a totally different format with different
# command syntax to get the info we need. 
# Get the info and return it in a format identical to the Linux one.
# Note: that is only the port not the listening part so from the    
#       *.port (instead of 0.0.0.0:port on linux) or ipaddr.port
#       we only want the port so use awks NF to get the last field
#       after the last . from that.
# Note2: SunOS can also have a listen address of *.* instead of
#        *.portnum as a local address unless we grep only on LISTEN
# ----------------------------------------------------------------------
identify_network_listening_processes_sunos() {
   # put ps into a workfile to avoid running it many times
   ps -ef > identify_network_listening_processes.wrk
   netstat -an -u -f inet | grep "LISTEN" | while read xx
   do
      listenport=`echo "${xx}" | awk {'print $1'}`
      pid=`echo "${xx}" | awk {'print $4'}`
      listenprocess=`get_process_by_exact_pid "${pid}"`
      if [ "${listenprocess}." != "." ]
      then
         # SunOS reports the port as *.port or nnn.nnn.nnn.nnn.port, the processing
	 # script expects only the port part so only keep that. That allows the
	 # existing Linux checks in the processing script to work unaltered.
         listenport=`echo "${listenport}" | awk -F\. {'print $NF'}`  # only keep the port
         echo "NETWORK_TCPV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
      else
         listenport=`echo "${listenport}" | awk -F\. {'print $NF'}`  # only keep the port
         listenprocess=`echo "${xx}" | awk {'print $5'}`
         echo "NETWORK_TCPV4_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
      fi
   done
   netstat -an -u -f inet6 | grep "LISTEN" | while read xx
   do
      listenport=`echo "${xx}" | awk {'print $1'}`
      pid=`echo "${xx}" | awk {'print $4'}`
      listenprocess=`get_process_by_exact_pid "${pid}"`
      if [ "${listenprocess}." != "." ]
      then
         listenport=`echo "${listenport}" | awk -F\. {'print $NF'}`  # only keep the port
         echo "NETWORK_TCPV6_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
      else
         listenport=`echo "${listenport}" | awk -F\. {'print $NF'}`  # only keep the port
         listenprocess=`echo "${xx}" | awk {'print $5'}`
         echo "NETWORK_TCPV6_PORT_${listenport}=${listenprocess}" >> ${LOGFILE}
      fi
   done
   # MID: TODO - the 'unix' socket handling
   /bin/rm identify_network_listening_processes.wrk
} # end of identify_network_listening_processes_sunos

# -------------------------------------------------------------------------------
# PAM is used on many systems to override the values in /etc/login.defs,
# however we do not check if PAM modules are loaded so even if the PAM configuration
# files exist we use the lowest entry in either to report/alert on.
#
# This routine returns the lowest value found in PAM configuration settings
# or an empty string "" if there are no uncommented minlen settings.
# -------------------------------------------------------------------------------
get_PAM_pwminlen() {
   # Check the default PAM pwquality file
   # If a default is set (uncommented) in the default config file
   # obtain that value.
   pamentry=`cat /etc/security/pwquality.conf 2>/dev/null | grep -v "^#" | grep "minlen"`
   if [ "${pamentry}." != "." ];
   then
      pamminlen=`echo "${pamentry}" | awk -F\= {'print $2'} | awk {'print $1'}`
      echo "${pamminlen}" > ${WORKDIR}/pamwork.tmp
   fi
   # Then check for any override custom files
   pamcustomcount=`ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | wc -l`
   if [ ${pamcustomcount} -gt 0 ];
   then
      # -h suppresses each filename: being listed in the output
      grep -h "minlen" /etc/security/pwquality.conf.d/*.conf 2>/dev/null | grep -v "^#" | awk -F\= {'print $2'} | awk {'print $1'} | while read pamminlen
      do
         echo "${pamminlen}" > ${WORKDIR}/pamwork.tmp
      done
   fi
   # If any values recorded get the minimum
   if [ -f ${WORKDIR}/pamwork.tmp ];
   then
      pamminlen=`cat ${WORKDIR}/pamwork.tmp | sort -nr | tail -1`
   else
      pamminlen=""
   fi
   echo "${pamminlen}"   # return value to the caller
} # end of get_PAM_pwminlen

# **********************************************************************
#                            MAINLINE STARTS
# **********************************************************************
# ======================================================================
# Record the server details
# ======================================================================
myhost=`hostname`
mydate=`date +"%Y/%m/%d %H:%M"`
mydate2=`date +"%s"`
oskernel=`uname -r`
ostype=`uname -s`
if [ -f /etc/os-release  ];
then
   osversion=`grep "PRETTY_NAME" /etc/os-release | awk -F\= {'print $2'} | sed -e 's/"//g'`
   if [ "${osversion}." == "." ];
   then
      osversion="No PRETTY_NAME in /etc/os-release"
   fi
else
   osversion="${ostype}"   # will put in SunOS for SunOS
fi
echo "TITLE_HOSTNAME=${myhost}" >> ${LOGFILE}
echo "TITLE_CAPTUREDATE=${mydate}" >> ${LOGFILE}
echo "TITLE_OSVERSION=${osversion}" >> ${LOGFILE}
echo "TITLE_OSKERNEL=${oskernel}" >> ${LOGFILE}
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
record_file ETC_HOSTS_ALLOW_FILE /etc/hosts.allow  # hosts that may connect
              # processing script to make sure no 'ALL: ALL: spawn' commands are executed 
	      # as even SNMP can get a backdoor script running that way
record_file ETC_HOSTS_DENY_FILE /etc/hosts.deny  # hosts that may not connect unless in hosts.allow
ostype=`uname -s`
if [ "${ostype}." != "SunOS." ];   # Linux checking reasonably coded
then
   record_file LOGIN_DEFS /etc/login.defs        # passwd maxage, minlen etc
   aa=`get_PAM_pwminlen`                         # see if minlen overridden by PAM settings
   echo "PAM_PWQUALITY_MINLEN=${aa}" >> ${LOGFILE}
else   # SunOS puts things in different places
   record_file ETC_DEFAULT_PASSWD /etc/default/passwd
fi

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
#find_perms_under_system_dir PERM_SYSTEM_FILE /    not all, be selective using the below
extract_as_unique_lines ${SYSTEM_DIR_LIST} | while read extractdirname
do
   find_perms_under_system_dir PERM_SYSTEM_FILE "${extractdirname}"
done
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
# Find all SUID file directories.
# From F20 (19?) -perm +6000 is not permitted to find both,
# we have to seperately search on -4000 and -2000 now
# Find from /, no limiting on mount points as we want all suid files
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
find_file_perm PERM_SHADOW_FILE /etc/shadow "root" "NA"

# N/A, I use postfix, users may use many different mail setups
# find_file_perm PERM_SENDMAIL_FILE /etc/sendmail.cf

# ======================================================================
# Find any orphaned files and directories (where owning uid has no
# matching user in /etc/passwd)
# ======================================================================
timestamp_action "searching for orphan directories and files"
find_orphans() {
   dirname="$1"
   find ${dirname} -mount -nouser -type d 2>/dev/null | while read xx
   do
      dirperms=`ls -la ${xx} | head -2 | tail -1 | awk {'print $1" "$2" "$3" "$4" "$5" "$6" "$7" "$8'}`
      echo "ORPHAN_DIR=${dirperms} ${xx}" >> ${LOGFILE}
   done
   find / -mount -nouser -type f -exec ls -la {} \; | while read xx
   do
      echo "ORPHAN_FILE=${xx}" >> ${LOGFILE}
   done
}
extract_as_unique_lines ${ALL_DIR_LIST} | while read extractdirname
do
   find_orphans "${extractdirname}"
done

# ======================================================================
# Are cron.allow and cron.deny being used ?
# ======================================================================
timestamp_action "collecting cron information"
ostype=`uname -s`
if [ "${ostype}." != "SunOS." ];
then
   basedir="/etc"
else
   basedir="/etc/cron.d"    # SunOS puts them in here
fi
if [ -f ${basedir}/cron.deny ];
then
   echo "CRON_DENY_EXISTS=YES" >> ${LOGFILE}
   cat ${basedir}/cron.deny | while read dataline
   do
      if [ "${dataline}." != "." ];    # only record non-blank lines
      then
         echo "CRON_DENY_DATA=${dataline}" >> ${LOGFILE}
      fi
   done
else
   echo "CRON_DENY_EXISTS=NO" >> ${LOGFILE}
fi
if [ -f ${basedir}/cron.allow ];
then
   echo "CRON_ALLOW_EXISTS=YES" >> ${LOGFILE}
   cat ${basedir}/cron.allow | while read dataline
   do
      if [ "${dataline}." != "." ];    # only record non-blank lines
      then
         echo "CRON_ALLOW_DATA=${dataline}" >> ${LOGFILE}
      fi
   done
else
   echo "CRON_ALLOW_EXISTS=NO" >> ${LOGFILE}
fi

# ======================================================================
# Collect permissions of jobs run by cron
# ======================================================================
# User cron jobs
# 0.12 added grep -v .SEQ to handle Ubuntu creating that file, a Ubuntu specific file
#      that of course caused false alerts when processed
# 0.13 added the subroutines below as parsing helpers to parse the crontab line
#      and rework code to use them.
# --------------------------------------------------------------------------------------------------------------
# Called by (a helper routine for) cron_parse_out_commands below
# Skip over any options (begining with -) between a command and its values
# NOTE: only handles concatatenated commands such as -svalue, not such as '-s value"
#       as that would require detailed knowledge of every possible program option
#       for every possible program, and handling for all
# Input: expected to be a
#     command [-options] file moredata
#     command [-options] "more data"
# Output: file moredata
# --------------------------------------------------------------------------------------------------------------
cron_parse_strip_options() {
   shift           # shift over system command
   xx="$1"
   while [ "${xx:0:1}." == "-." ]
   do
      shift
      xx="$1"
   done
   # check for "" around the command, strip off if present
   xx="$*"
   if [ "${xx:0:1}." == "\"." ];
   then
      xx="${xx:1:${#xx}}"
      if [ "${xx:$((${#xx} - 1)):1}." == "\"." ];
      then
         xx = ${xx:0:$((${#xx} - 1))}
      fi
   fi
   echo "${xx}"
} # end cron_parse_strip_options

# --------------------------------------------------------------------------------------------------------------
#
# Parse out commands from complex crontab lines to extract all commands
# being run on the line so all can be checked for file permissions.
# In cases where 'shells' are the command use the second parm as the
# file to be permission checked.
# In cases where all checks are invalidated, such as the 'cd' command
# being used making it impossible to locate references to files in
# later concatenated commands on the same line mark it fatal.
#
# Input: expected to be a valid crontab command line
# Output: as many lines as needed for stacked commands of
#    FATAL:command:any text                cannot be checked for permissions by mainline code as environment changed
#    IGNORE:command:any text               commands that do nothing or cannot be checked
#    NOTFOUND:command:any text             commands that could not be located on the server, so cannot be checked
#    USABLE:command:any text               commands that can be checked by mainline code
# Note: mainline code does all the work with the resulting output; this routine is for parsing commands out only
#
# --------------------------------------------------------------------------------------------------------------
cron_parse_out_commands() {
   # shift over the five time fields, MUST assume space delimiter and not tab
   var1=`echo "$1" | cut -d " " -f 6-999`
   # Bug found trying on SunOS, where commands are embedded inside [ ] fields
   var1=`echo "${var1}" | sed -e's/\[ -x //g' | sed -e's/\[//'g | sed -e's/\]//'g` # remove them
   # and the rest of the data is the commands to check
   while [ ${#var1} -gt 0 ];
   do 
      wasandand="no"
      var2=`echo "${var1}" | awk -F\; {'print $1'}`     # test for commands stacked with ;
      var3=`echo "${var1}" | awk -F\& {'print $1'}`     # test for commands stacked with &&
      var4=`echo "${var1}" | awk -F\| {'print $1'}`     # test for commands stacked with | pipe
      len2=${#var2}
      len3=${#var3}
      len4=${#var4}
      # workaround, & may not be &&, it may be 2>&1
      if [ ${len3} -gt 2 ];
      then
         testvar=${var3:((${len3} - 2)):2}
         if [ "${testvar}." == "2>." ];    # was 2>&n syntax, cannot use as end of command
         then
            var3="${var2}"                 #  so replace with the ; search text
            len3=${len2}                   #  and length
         fi
      fi
      if [ ${len3} -lt ${len2} -a ${len3} -lt ${len4} ];    # truncated on a &
      then
         uselen=${len3}
         wasandand="yes"
      else
         if [ ${len2} -lt ${len4} ];                    # was trucation on ;
         then
            uselen=${len2}                              #   yes, use that
         else
            uselen=${len4}                              #   no, use pipe (or no match) length
         fi
      fi
      cmdtest=${var1:0:${uselen}}
      # if and the end of a stacked command list in " may have reached last command so strip last "
      if [ "${cmdtest:$((${#cmdtest} - 1)):1}." == "\"." ];
      then
         cmdtest=${cmdtest:0:$((${#cmdtest} - 1))}
      fi
      firstpart=`echo "${cmdtest}" | awk {'print $1'}`
      if [ "${firstpart:0:1}." != "/". ];   # if not full path find the file
      then
         cmdexists=`which ${firstpart} 2>/dev/null | grep -v "no ${firstpart} in"`
      else
         cmdexists="${firstpart}"
      fi
      if [ "${cmdexists}." == "." ];                    # if 'which' found no result
      then
         isfatal="yes"
      else
         firstpart="${cmdexists}"                       # for messages expand to full path is which found it
         isfatal=`echo "${CRON_CMD_FATAL_LIST}" | grep -w "${cmdexists}"`  
      fi
      if [ "${isfatal}." != "." ];
      then
         echo "FATAL:${cmdexists}:cannot be checked, ${cmdtest}, in fatal list"
      else
         if [ "${cmdexists}." != "." ];
         then
            isignore=`echo "${CRON_CMD_IGNORE_LIST}" | grep -w "${cmdexists}"`
            issystem=`echo "${CRON_CMD_SHELL_LIST}" | grep -w "${cmdexists}"`
         else
            isignore=""
            issystem=""
         fi
         if [ "${issystem}." != "." ];
         then
            # something like 'php file' or 'bash file' so get the file
            cmdtest=`cron_parse_strip_options ${cmdtest}`   # skipping any -X options between command and file
            cmdtest=`echo "${cmdtest}" | awk {'print $1'}`    # only want filename, ignore trailing data
            firstpart=`echo "${cmdtest}" | awk {'print $1'}`
         fi
         if [ "${isignore}." == "." ];
         then
            if [ "${firstpart:0:1}." != "/". ];   # if not full path find the file
            then
               cmdexists=`which ${firstpart} 2>/dev/null | | grep -v "no ${firstpart} in"`
            else                                  # else use what was provided as full path
               cmdexists="${firstpart}"
            fi
            if [ "${cmdexists}." != "." ];        # do not check for an empty value (possible if 'which' was used and no file found)
            then
               if [ ! -f ${cmdexists} ];          # if file/command does not exist cannot use it
               then                               # note: cannot check for -x as it may be a readable file into php/bash etc.
                  cmdexists=""
               fi
            fi
            if [ "${cmdexists}." == "." ];
            then 
               echo "NOTFOUND:${firstpart}:${cmdtest}"
            else
               echo "USABLE:${cmdexists}:${cmdtest}"
            fi
         else
            echo "IGNORE:${cmdexists}:${cmdtest}"
         fi
      fi
      if [ "${wasandand}." == "yes." ];
      then
         var1=${var1:$((${uselen}+2)):${#var1}}
      else
         var1=${var1:$((${uselen}+1)):${#var1}}
      fi
   done
} # end of cron_parse_out_commands

# --------------------------------------------------------------------------------------------------------------
# Now actually do the checks of the crontab lines, using the subroutines above to assist
# --------------------------------------------------------------------------------------------------------------
find /var/spool/cron -type f 2>/dev/null | grep -v ".SEQ" | while read dataline
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
         echo "CRONTAB_DATA_LINE=${crontabowner} crontab:@${crontabline}" >> ${LOGFILE}
         cron_parse_out_commands "${crontabline}" | while read commanddata
         do
            respcode=`echo "${commanddata}" | awk -F: {'print $1'}`
            case "${respcode}" in
               "USABLE")
                       actualcmd=`echo "${commanddata}" | awk -F: {'print $2'}`
                       resultdata=`find_file_perm_nolog PERM_CRON_JOB_FILE ${actualcmd} "${crontabowner}" "crontab"`
                       if [ "${resultdata}." != "." ];
                       then
                          echo "${resultdata}@${crontabline}" >> ${LOGFILE}
                       else # record crontab lines we could not check file perms for
                            # these will be lines with commands such as 'cd xxx;./command'
                          echo "NO_PERM_CRON_JOB_FILE=${crontabowner} crontab:@${crontabline}@${actualcmd}" >> ${LOGFILE}
                       fi
                       ;;
               "NOTFOUND"|"FATAL")
                       actualcmd=`echo "${commanddata}" | awk -F: {'print $2'}`
                       echo "NO_PERM_CRON_JOB_FILE=${crontabowner} crontab:@${crontabline}@${actualcmd}" >> ${LOGFILE}
                       ;;
               *)      # must be IGNORE
                       actualcmd=`echo "${commanddata}" | awk -F: {'print $2'}`
                       echo "IGNORE_PERM_CRON_JOB_FILE=${crontabowner} crontab:@${crontabline}@${actualcmd}" >> ${LOGFILE}
                       ;;
            esac
         done
      fi   # if contab line len gt 10
   done
done
# --------------------------------------------------------------------------------------------------------------
# Done with the helper subroutines
# --------------------------------------------------------------------------------------------------------------
unset cron_parse_strip_options
unset cron_parse_out_commands

# ======================================================================
# Are at.allow and at.deny being used ?
# ======================================================================
ostype=`uname -s`
if [ "${ostype}." != "SunOS." ];
then
	basedir="/etc"
else
	basedir="/etc/cron.d"   # SonOS puts them here
fi
if [ -f ${basedir}/at.deny ];
then
   echo "CRON_AT_DENY_EXISTS=YES" >> ${LOGFILE}
   cat ${basedir}/at.deny | while read dataline
   do
      if [ "${dataline}." != "." ];    # only record non-blank lines
      then
         echo "CRON_AT_DENY_DATA=${dataline}" >> ${LOGFILE}
      fi
   done
else
   echo "CRON_AT_DENY_EXISTS=NO" >> ${LOGFILE}
fi
if [ -f ${basedir}/at.allow ];
then
   echo "CRON_AT_ALLOW_EXISTS=YES" >> ${LOGFILE}
   cat ${basedir}/at.allow | while read dataline
   do
      if [ "${dataline}." != "." ];    # only record non-blank lines
      then
         echo "CRON_AT_ALLOW_DATA=${dataline}" >> ${LOGFILE}
      fi
   done
else
   echo "CRON_AT_ALLOW_EXISTS=NO" >> ${LOGFILE}
fi

# ======================================================================
# Collect basic network info to be checked
# ======================================================================
timestamp_action "searching for user network files that may pose a risk"
# --- Any equiv files on the server ? ---
if [ -f /etc/hosts.equiv ];
then
   find_file_perm PERM_HOSTS_EQIV_SYSTEM "/etc/hosts.equiv" "root" "NA"
   record_file HOSTS_EQIV /etc/hosts.equiv
fi
if [ -f /etc/ssh/shosts.equiv ];
then
   find_file_perm PERM_HOSTS_EQIV_SYSTEM "/etc/ssh/shosts.equiv" "root" "NA"
   record_file HOSTS_EQIV /etc/ssh/shosts.equiv
fi
find / -name ".rhosts" 2>/dev/null | while read dataline
do
   find_file_perm PERM_HOSTS_EQIV_USER "${dataline}" "NA" "NA"
   record_file HOSTS_EQIV ${dataline}
done
find / -name ".shosts" 2>/dev/null | while read dataline
do
   find_file_perm PERM_HOSTS_EQIV_USER "${dataline}" "NA" "NA"
   record_file HOSTS_EQIV ${dataline}
done

# --- How about any file shares ? ---
timestamp_action "checking for exported filesystems"
ostype=`uname -s`
if [ "${ostype}." != "SunOS" ];
then
   if [ -f /etc/exports ];
   then
      find_file_perm PERM_ETC_EXPORTS "/etc/exports" "root" "NA"
      record_file ETC_EXPORTS_DATA /etc/exports
      cat /etc/exports | while read dataline
      do
          dirtocheck=`echo "${dataline}" | awk {'print $1'}`
          find_dir_perm PERM_EXPORTED_DIR ${dirtocheck} "root"
      done
   fi
else   # Must be SunOS
   if [ -f /etc/dfs/dfstab ];
   then
      find_file_perm PERM_ETC_DFS_DFSTAB "/etc/dfs/dfstab" "root" "NA"
      record_file ETC_DFS_DFSTAB_DATA /etc/dfs/dfstab
      cat /etc/dfs/dfstab | while read dataline
      do
          # SunOS has it as a share command with teh dir as the last value
	  # before a comment
	  # ie: share -F nfs -o rw=client1:client2 -d "description" /path/to/share
	  # so first awk is to drop off any comment
          dirtocheck=`echo "${dataline}" | awk -F\# {'print $1'} | awk {'print $NF'}`
          find_dir_perm PERM_EXPORTED_DIR ${dirtocheck} "root"
      done
   fi
fi

# --- record any users with authorized_keys files
cat /etc/passwd | while read pwline
do
   username=`echo "${pwline}" | awk -F: {'print $1'}`
   userdir=`echo "${pwline}" | awk -F: {'print $6'}`
   if [ -f ${userdir}/.ssh/authorized_keys ];    # ~${username}/.ssh syntax does not work, need full homedir
   then
      echo "USER_HAS_AUTHORIZED_KEYS=${username}" >> ${LOGFILE}
      # for rsa keys we can extract the hostnames they are for
      grep "ssh-rsa" ${userdir}/.ssh/authorized_keys | awk '{print $NF}' | while read userhost
      do
         echo "USER_RSA_KEYS_FOR=${username}:${userhost}" >> ${LOGFILE}
      done
      # if there are non-rsa keys just record the total number of them
      otherkeys=`grep -v "ssh-rsa" ${userdir}/.ssh/authorized_keys | wc -l`
      echo "USER_NOTRSA_KEYS_COUNT=${username}:${otherkeys}" >> ${LOGFILE}
   fi
done

# --- what ports are being listened to ? ---
# try to match a running process to any listening network port
# MID: 2025/12/10 - not valid on openindianna so
timestamp_action "collecting information on open network ports and sockets"
OStypeName=`uname -s`
case "$OStypeName" in
   "Linux")
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
            identify_network_listening_processes
            ;;
   "SunOS")  # MID: TODO, put it into linux format, tricky have to imbed :: for v6 plus tcp/tcp6 header
	    # But that means the complicated work in the processing script does not
	    # need to be messed about with.
	    # SunOS format is for V4
	    #   *.port  *  *  userid pid program-name 0 0 bufsize?
	    #   nnn.nnn.nnn.nnn.port  *  *  userid pid program-name 0 0 bufsize?
	    # Need the format rewritten to Linux format which is
	    #   tcp 0 0 0.0.0.0:port  0.0.0.0:* LISTEN pid/program
	    #   tcp 0 0 nnn.nnn.nnn.nnn:port  0.0.0.0:* LISTEN pid/program
            netstat -an -u -f inet | grep LISTEN | while read dataline
            do
               portfield=`echo "${dataline}" | awk {'print $1'}`
               iswildcard=`echo "${portfield}" | grep '^*.'`    # will be *.port if wildcard
               portnum=`echo "${portfield}" | awk -F\. '{print $NF}'`
               if [ "${iswildcard}." != "." ];
               then
                  ipaddr="0.0.0.0"
               else
                  ipaddr=`echo "${portfield}" | awk -F\. '{print $1"."$2"."$3"."$4}'`
               fi
               pidfield=`echo "${dataline}" | awk {'print $5'}`
               pgmfield=`echo "${dataline}" | awk {'print $6'}`
               echo "PORT_TCPV4_LISTENING=tcp 0 0 ${ipaddr}:${portnum} 0.0.0.0:* LISTEN ${pidfield}/${pgmfield}" >> ${LOGFILE}
            done
	    # SunOS format is for V6
	    #   *.port  *  *  userid pid program-name 0 0 bufsize?
	    #   ::1.port  *  *  userid pid program-name 0 0 bufsize?
	    # Need the format rewritten to Linux format which is
	    #   tcp6 0 0 :::port :::* LISTEN pid/program
	    #   tcp6 0 0 ::1:port :::* LISTEN pid/program
            netstat -an -u -f inet6 | grep LISTEN | while read dataline
            do
               portfield=`echo "${dataline}" | awk {'print $1'}`
               iswildcard=`echo "${portfield}" | grep '^*.'`    # will be *.port if wildcard
               portnum=`echo "${portfield}" | awk -F\. '{print $NF}'`
               if [ "${iswildcard}." != "." ];
               then
                  ipaddr=":::${portnum}"
               else
                  listenv6=`echo "${portfield}" | awk -F\. {'print $1'}`
                  ipaddr="${listenv6}:${portnum}"
               fi
               pidfield=`echo "${dataline}" | awk {'print $5'}`
               pgmfield=`echo "${dataline}" | awk {'print $6'}`
               echo "PORT_TCPV6_LISTENING=tcp6 0 0 ${ipaddr} :::* LISTEN ${pidfield}/${pgmfield}" >> ${LOGFILE}
            done
            identify_network_listening_processes_sunos
            ;;
   *)
            echo "*Warn* OS type ${isLinux} not supported for network info collection yet"
            ;;
esac

# Whats in the services file
timestamp_action "recording services file"
record_file SERVICES_FILE /etc/services

# A few checks to see if samba is running
timestamp_action "checking for samba"
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

timestamp_action "searching for firewall rules"
# iptables ACCEPT rules
#haveiptables=`which iptables 2>/dev/null`   # SunOS does not redirect error to 2, so grep out the err string
haveiptables=`which iptables 2>/dev/null | grep -v "no iptables in"`
if [ "${haveiptables}." != "." ];
then
   timestamp_action "collecting firewall rules from iptables"
   iptables -n -v -L | while read dataline
   do
      echo "IPTABLES_FULLDATA=${dataline}" >> ${LOGFILE}
   done
else
   timestamp_action "- iptables command not installed, cannot collect firewall rules using iptables"
fi
# F32/CentOS8/RHEL8 if using firewalld now use nftables instead of iptables
#haveiptables=`which nft 2>/dev/null`   # SunOS does not redirect error to 2, so grep out the err string
havenft=`which nft 2>/dev/null | grep -v "no nft in"`
if [ "${havenft}." != "." ];
then
   timestamp_action "collecting firewall rules from netfilter"
   nft list ruleset | while read dataline
   do
      echo "NFTABLES_FULLDATA=${dataline}" >> ${LOGFILE}
   done
# else no issue, netfilter is not on servers prior to F23/C8/RH8 by default
else
   timestamp_action "- nft command not installed, cannot collect firewall rules using netfilter"
fi

# record if NetworkManager and Firewalld are running on the server
OStypeName=`uname -s`
if [ "${OStypeName}." == "Linux." ]
then
   timestamp_action "testing for NetworkManager and Firewalld service status"
   testfornm=`systemctl status NetworkManager.service | grep 'Active: active (running)'`
   if [ "${testfornm}." != "." ];
   then
      echo "NETWORKMANAGER=YES" >> ${LOGFILE}
   else
      echo "NETWORKMANAGER=NO" >> ${LOGFILE}
   fi
   testfornm=`systemctl status firewalld.service | grep 'Active: active (running)'`
   if [ "${testfornm}." != "." ];
   then
      echo "FIREWALLD=YES" >> ${LOGFILE}
   else
      echo "FIREWALLD=NO" >> ${LOGFILE}
   fi
else
   # Then in my ENV must be SunOS that has neither of the two above
   # TODO: find and record the equivalent
   echo "NETWORKMANAGER=NO" >> ${LOGFILE}
   echo "FIREWALLD=NO" >> ${LOGFILE}
fi

# ======================================================================
# motd should contain a auth/business notice.
# as should the sshd config, check root login flag here also
# ======================================================================
timestamp_action "collecting motd and ssh-banner information"
record_file MOTD_DATA /etc/motd
find_file_perm PERM_ETC_MOTD "/etc/motd" "root" "NA"
# MID: 2008/07/03 added sshd config and banner capture
if [ -f /etc/ssh/sshd_config ];
then
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
# SSH config settings, global and per user should be checked
# processing sript to check/alert on any in sshd_gonfig global
#     AuthorisedKeysCommand
#     AuthorisedKeysCommandUser
# and in user ssh configs for any
#     ProxyCommand
# ======================================================================
timestamp_action "collecting global ssh config info"
record_file SSHD_CONFIG_DATA /etc/ssh/sshd_config

timestamp_action "collecting user ssh config info"
# User SSH config files should ideally not have any 'ProxyCommand'
cat /etc/passwd | while read dataline
do
	homedir=`echo "${dataline}" | awk -F: {'print $6'}`
	if [ -f ${homedir}/.ssh/config ];
	then
	   userid=`echo "${dataline}" | awk -F: {'print $1'}`
	   record_file USER-SSH-CONFIG-${userid} "${homedir}/.ssh/config"
	fi
	# If a rc file exists these are commands to be run when a user
	# ssh session is established, record those for the processing
	# check script to look at as dangerous/back-door commands can
	# slip into those.
	if [ -f ${homedir}/.ssh/rc ];
	then
	   userid=`echo "${dataline}" | awk -F: {'print $1'}`
	   record_file USER-SSH-RC-${userid} "${homedir}/.ssh/rc"
	fi
done

# While we are getting user ssh info also save their .ssh directory permissions
# to ensure only they can access the files under it.
find /home -type d -name ".ssh" | while read sshdir
do
   dirperms=`ls -la "${sshdir}" | grep "^d" | head -1 | awk {'print $1":"$3'}`  # perms:owner
   echo "USER-SSH-DIRPERMS=${sshdir}:${dirperms}" >> ${LOGFILE}      #dir:perms:owner
done

# ======================================================================
# Files that must exist and be retained for a specific period (days)
# ======================================================================
if [ "${OStypeName}." == "Linux." ]
then
   timestamp_action "collecting info on files that must be retained"
   require_file /var/log/auth.log 60 ".gz"
   require_file /var/log/wtmp 60 ".gz"
fi
# TODO: find SunOS equivalent

# ======================================================================
# Record all processes that are running at the time the snapshot ran.
# ======================================================================
timestamp_action "recording running process list"
ps -ef | while read dataline
do
   echo "PROCESS_RUNNING=${dataline}" >> ${LOGFILE}
done

# ======================================================================
# Collect the contents of the wtmp log using the 'last' command.
# Plus user last logged on info for all users using lastlog
# ======================================================================
# Debian13 has obsoleted WTMP and the last and lastlog commands
havelast=`which last | grep -v "no last in"`
if [ "${havelast}." != "." ];
then
   timestamp_action "recording last login information"
   if [ "${OStypeName}." == "Linux." ];  # Again SunOS bites, -i is not a valid option
   then
      last -i | while read dataline
      do
         echo "WTMP_LAST_LOG=${dataline}" >> ${LOGFILE}
      done
      lastlog | while read dataline
      do
         echo "LASTLOG_ENTRY=${dataline}" >> ${LOGFILE}
      done
   elif [ "${OStypeName}." == "SunOS." ];  # Again SunOS bites, -i is not a valid option
   then
      last | while read dataline
      do
         echo "WTMP_LAST_LOG=${dataline}" >> ${LOGFILE}
      done
      # SunOS soes not have 'lastlog'
      # TODO: find equivalent of showing when users last logged in if ever
   fi
fi

# ======================================================================
# Collect the interface information.
# ======================================================================
timestamp_action "recording interface information"
if [ "${OStypeName}." == "Linux." ]
then
   ip a | while read dataline
   do
      echo "INTERFACE_INFO_IPA=${dataline}" >> ${LOGFILE}
   done
else  # SunOS does not have ip command
   ifconfig -a | while read dataline
   do
      echo "INTERFACE_INFO_IFCONFIG=${dataline}" >> ${LOGFILE}
   done
fi

# ======================================================================
# Collect the selinux settings.
# ======================================================================
timestamp_action "recording selinux information"
if [ -f /etc/selinux/config ];   # exists if selinux-policy is installed
then
   echo "SELINUX_INSTALLED=yes" >> ${LOGFILE}
   grep -v "^#" /etc/selinux/config | while read xx
   do
      if [ "${xx}." != "." ];
      then
         echo "${xx}" >> ${LOGFILE}
      fi
   done
   selinux_current=`getenforce`
   echo "SELINUX_CURRENT_GETENFORCE=${selinux_current}" >> ${LOGFILE}
else
   echo "SELINUX_INSTALLED=no" >> ${LOGFILE}
fi

# ======================================================================
# Record contents of /etc/sudoers, ignoring comments and blank lines.
# ======================================================================
if [ -f /etc/sudoers ];
then
   timestamp_action "recording sudoers information"
   # Ignore comments and change tab control characters to spaces while recording these
   cat /etc/sudoers | grep -v "^#" | sed -e's/\t/ /g' | while read dataline
   do
      if [ "${dataline}." != "." ];
      then
         echo "SUDOERS=${dataline}" >> ${LOGFILE}
      fi
   done
   # Also append any site specific entries from /etc/sudoers.d and any
   # other directories configured by the '#includedir /full/dirname' option.
   grep -i "^#includedir" /etc/sudoers | awk {'print $2'} | while read dirname
   do
      if [ -d ${dirname} ];
      then
         ls ${dirname} | while read fname
         do
            basefname=`basename ${fname}`
            cat ${dirname}/${basefname} | grep -v "^#" | sed -e's/\t/ /g' | while read dataline
            do
               if [ "${dataline}." != "." ];
               then
                  echo "SUDOERS=${dataline}" >> ${LOGFILE}
               fi
            done
         done
      else
         timestamp_action ".   Warning: directory '#includedir ${dirname}' specified in /etc/sudoers does not exist"
      fi
   done
   # REPEAT for Debian - debian11 uses @includedir rather than #includedir
   # repeat the whole lot, so not want a wildcard match on character 1
   grep -i "^@includedir" /etc/sudoers | awk {'print $2'} | while read dirname
   do
      if [ -d ${dirname} ];
      then
         ls ${dirname} | while read fname
         do
            basefname=`basename ${fname}`
            cat ${dirname}/${basefname} | grep -v "^#" | sed -e's/\t/ /g' | while read dataline
            do
               if [ "${dataline}." != "." ];
               then
                  echo "SUDOERS=${dataline}" >> ${LOGFILE}
               fi
            done
         done
      else
         timestamp_action ".   Warning: directory '@includedir ${dirname}' specified in /etc/sudoers does not exist"
      fi
   done
fi

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
   OStypeName=`uname -s`
   case "${OStypeName}" in
      "Linux")
               isDebian=`uname -a | grep -i Debian`
               if [ "${isDebian}." == "." ];
               then
                  rpm -qa > ${RPMFILE}
               else
                  apt list --installed > ${RPMFILE}
               fi
               ;;
      "SunOS")
               pkg list > ${RPMFILE}
               ;;
      *) echo "*Warn* OS type ${OStypeName} not yet supported for package info collection"
               ;;
   esac
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
