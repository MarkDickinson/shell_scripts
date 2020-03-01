#!/bin/bash
# !!! WILL ONLY WORK WITH BASH !!! - needs bash substring facility
# ======================================================================
#
# process_server_details.sh
#
# Part of the server security checking suite.
#
# useage: process_server_details.sh [ rawfilesdir [archivedir [movetargetdir]]]
#      rawfilesdir is where the collected snapshots are
#      archivedir can be used to take an archive of the results
#      movetargetdir will move ../results/* to that dir on completion
#
# function:
#    will read all server extract files named secaudit_<hostname>.txt
#    and produce an html documentation system for each server, highlighting
#    security deviations and recording the servers key configuration
#    data files.
#
# Checks to be done
#   A. Users
#      A.1 - Check users all have unique uids
#      A.2 - must have a password (check against shadow entries)
#      A.3 - home directories must be secure, and must exist
#      A.4 - check users against ftpuser deny entries, no system users should be omitted
#            (yes, A.3 should be in B.3, but we need the files from A so 'so be it'.
#      A.5 - /etc/shadow must be tightly secured
#   B. Network access
#      B.1 - check system host equivalences files
#      B.2 - check user host equivalences files and security of
#      B.3 - check NFS file shares
#      B.4 - check SAMBA
#   C. Network Connectivity
#      C.1 - compare listening ports against allowed ports
#      C.2 - check services/portconf file for insecure applications ?
#   D. Cron security
#      D.1 - all cronjob script files secured tightly, to correct owner
#   E. System file security
#      E.1 - all system files must be secured tightly
#      E.2 - check files with suid bits set (2007/08/23)
#   F. Server environment
#      F.1 - motd must exist and contain reqd keywords
#      F.2 - security log retention checks
#      F.3 - sshd configuration checks
#   G. Report on custom file used (if any)
#   Z. Record /etc file settings for the server
#
# MID: 2004/xx/xx - initial version needing a lot of work
# MID: 2007/01/02 - small change, now I have selinux in enforcing mode
#                   I needed to add a chcon on the output directory so
#                   the web server can access the reports.
# MID: 2007/08/02 - changed greps thru file to ^xx where I know the   
#                   string being searched for is at the beginning of
#                   the line to speed things up a bit. Added a force
#                   owner ok option also as vcsa owns one (1) system
#                   file [so i don't want it in the system owner list]
#                   but boy will this slow things down.
# MID: 2007/08/23 - started collecting files with suid bits set so have
#                   added processing for that plus a new SUID_ALLOW
#                   option from the custom file for the servers.
# MID: 2008/07/03 - added F.3 for simple ssh config checks
# MID: 2010/09/22 - (1) truncated dir perms to get rid of the trailing .
#                       put onto the ls -la display since FC11 to show
#                       it has an selinux context, it broke all checks.
#                   (2) added the hwprof steps to include a link to
#                       the server hardware profile that is now being
#                       retrieved in the configuration collection.
#                   (3) Cleaned up suid list display
# MID: 2011/08/17 - (1) truncated dir perms to get rid of the trailing .Allow 555
#                       and 550 as valid allow_dirperm_system checks
# MID: 2019/12/20 - (1) fixed sshd banner checks, fixed shadow perm checks.
#                   (2) got tcp6 and udp6 checks working properly.
#                   (3) Permit users snort and puppet to own system files by default.
#                   (4) allow addition of more system file owners in custom files
#                       with ADD_SYSTEM_FILE_OWNER=xxx
# MID: 2020/02/17 - Version 0.04     
#                   (1) added additional flags allowed in custom files     
#                         ALLOW_VAR_FILE_GROUPWRITE=YES
#                         FORCE_ANYFILE_OK=filebasename explicitperms
#                       documentation updated, refer to that for usage
#                   (2) removed the chcon of the results files, no longer
#                       relevant to my environment.
# MID: 2020/02/21 - Version 0.05     
#                   (1) 'bash' now preserves changes within a do/done loop
#                       (changed values now available outside loop) so I
#                       have added proper parameter handling
#                       (todo:revist those loops that use files to store
#                       and recall values upadted within loops as file
#                       storage is no longer necesary (unless bash changes
#                       again).
#                   (2) Implemeted the ability to reprocess a single server
#                       along with the checks to re-process others if needed
#                       to maintain consistency between versions.
#                   (3) Added special checks for files under /var/spool/mail
#                       which should be secured userid:mail where userid
#                       matches the filename and the user exists.
#
# ======================================================================
# defaults that can be overridden by user supplied parameters
SRCDIR=""         # where are the raw datafiles to process (required)
ARCHIVEDIR=""     # if populated archive the reports to here also (optional)
SINGLESERVER=""   # process all servers by default if this is not populated (optional)
while [[ $# -gt 0 ]];
do
   parm=$1
   key=`echo "${parm}" | awk -F\= {'print $1'}`
   value=`echo "${parm}" | awk -F\= {'print $2'}`
   case "${key}" in
      "--archivedir") ARCHIVEDIR="${value}"
                   shift
                   ;;
      "--datadir") SRCDIR="${value}"
                   shift
                   ;;
      "--oneserver") SINGLESERVER="${value}"
                   shift
                   ;;
      *)          echo "Unknown paramater value ${key}"
                  echo "Syntax:$0 --datadir=<directory> [--archivedir] [--oneserver=<servername>] [--reportdir=<dirname>]"
                  echo "Please read the documentation."
                  exit 1
                   ;;
   esac
done

# defaults that we need to set, not user overrideable
PROCESSING_VERSION="0.05"
MYDIR=`dirname $0`
MYNAME=`basename $0`
cd ${MYDIR}                           # all prcessing relative to script bin directory
# want filenames relative to ../ as a full filesystem path
temppos=`basename ${MYDIR}`           # save current dirname (don't assume always bin)
cd ..                                 # up one
BASEDIR=`pwd`                         # save filesystempath to here
cd ${temppos}                         # back to current dirname
checkdir=`echo "${BASEDIR}" | grep "_"`
if [ "${checkdir}." != "." ];
then
   echo "*FATAL* no part of the directory path the application is run from"
   echo ".       is permitted to contain the underscore ( _ ) character."
   echo ".       That would break all the script parsing logic."
   echo "You have installed this toolkit under ${BASEDIR}"
   exit 1
fi
WORKDIR="${BASEDIR}/workfiles"
RESULTS_DIR="${BASEDIR}/results"
OVERRIDES_DIR="${BASEDIR}/custom"
PERM_CHECK_RESULT="OK"
NUM_VALUE=0      # used a lot
CUSTOMFILE=""                        # set on a per server being processed basis

# Space seperated list of users that can own files of class SYSTEM.
# Additional users can be added on a per server basis from the server
# customisation file with ADD_SYSTEM_FILE_OWNER=xx
# NOTE: THIS LIST IS ACTUALLY INITIALISED IN update_system_file_owner_list
#       FOR EACH SERVER SO IF YOU CHANGE THE BELOW ALSO CHANGE IT THERE.
SYSTEM_FILE_OWNERS=""

# Added below for single server processing. Can contain
# a list of additional servers that also need processing
# based on the sanity checks done on what is needed to
# correctly recreate the main index.
SINGLE_ADDITIONALS="${WORKDIR}/additional_servers"

# html colour codes to brighten things up
colour_OK="#CCFFE6"
colour_warn="#FDFFCC"
colour_alert="#FF8040"
colour_banner="#C0C0C0"

# ------------------------------------------------------------
# Lets sanity check the user input
# ------------------------------------------------------------
# Ensure we were given a source directory
if [ "${SRCDIR}." == "." ];
then
   echo "*Error* no data files directory was specified"
   exit 1
fi
testroot=${SRCDIR:0:1}
if [ "${testroot}." != "/." ];
then
   SRCDIR="${BASEDIR}/${SRCDIR}"   
fi
if [ ! -d ${SRCDIR} ];
then
   echo "*Error* data files directory ${SRCDIR} does not exist"
   exit 1
fi
# If an archive directory was specified it must exist using full path name
if [ "${ARCHIVEDIR}." != "." ];
then
   testroot=${ARCHIVEDIR:0:1}
   if [ "${testroot}." != "/." ];
   then
      ARCHIVEDIR="${BASEDIR}/${ARCHIVEDIR}"   
   fi
   if [ ! -d ${ARCHIVEDIR} ];
   then
      echo "*Error* archive directory ${ARCHIVEDIR} does not exist"
      exit 1
   fi
fi

# Ensure there are valid collector files in the source directory
# Set the files to process to the default of all available if there are.
testvar=`ls ${SRCDIR}/secaudit*txt 2>/dev/null | wc -l | awk {'print $1'}`
if [ ${testvar} -lt 1 ]; # no matching files
then
   echo "There are no valid files in ${SRCDIR}, nothing to do"
   exit 1
fi
FILES_TO_PROCESS="${testvar}"
FILES_PROCESSED=0

# ===========================================================
#                       helper tasks
# ===========================================================

log_message() {
   textmsg="$1"
   logtime=`date +"%d-%m-%Y %H:%M"`
   echo "${logtime} - ${textmsg}"
} # log_message

clean_prev_work_files() {
   if [ -d ${WORKDIR} ];
   then
      rm -rf ${WORKDIR}
   fi
} # clean_prev_work_files

delete_file() {
   filename="$1"
   if [ -f ${filename} ];
   then
      rm -f ${filename}
   fi
} # delete_file

# wc -l puts spaces in front of the number returned
# this will chop it off.
get_num_only() {
	numval=$1
	NUM_VALUE=${numval}
} # get_num_only

# ---------------------------------------------------------------
# Routines to update counter files in server specific directories
clear_counter() {
   hostid="$1"
   type="$2"
   filename="${RESULTS_DIR}/${hostid}/${type}"
   echo "0" > ${filename}
}

add_to_counter() {
   hostid="$1"
   type="$2"
   numtoadd="$3"
   filename="${RESULTS_DIR}/${hostid}/${type}"
   if [ ! -f ${filename} ];
   then
      clear_counter "${hostid}" "${type}"
   fi
   testvar=`cat ${filename}`
   if [ "${testvar}." == "." ];
   then
      testvar=0
   fi
   testvar=$((${testvar} + ${numtoadd}))
   echo "${testvar}" > ${filename}
} # add_to_counter

inc_counter() {
   hostid="$1"
   type="$2"
   add_to_counter "${hostid}" "${type}" "1"
   delete_file ${WORKDIR}/${hostid}_all_ok
} # inc_counter

# ---------------------------------------------------------------
# Used to update counter files in the global resutls
# directory (previous procs are specific to host names)
update_globals() {
   num="$1"
   counterfile="$2"
   filename="${RESULTS_DIR}/${counterfile}"
   if [ ! -f ${filename} ];
   then
      echo "0" > ${filename}
   fi
   testvar=`cat ${filename}`
   if [ "${testvar}." == "." ];
   then
      testvar=0
   fi
   testvar=$((${testvar} + ${num}))
   echo "${testvar}" > ${filename}
} # update_globals

# ---------------------------------------------------------------
#                    locate_custom_file
# Identify any customisation server for the server being
# processed.
# ---------------------------------------------------------------
locate_custom_file() {
   serverid="$1"
   CUSTOMFILE=""     # default is no custom file for a server
   if [ -f ${OVERRIDES_DIR}/ALL.custom ];
   then
      CUSTOMFILE="${OVERRIDES_DIR}/ALL.custom"
   fi
   if [ -f ${OVERRIDES_DIR}/${serverid}.custom ];
   then
      CUSTOMFILE="${OVERRIDES_DIR}/${serverid}.custom"
   fi
   if [ "${CUSTOMFILE}." == "." ];
   then
      log_message "No customisation file is being used for server ${serverid}"
   else
      log_message "Using customisation file ${CUSTOMFILE}"
   fi
} # end of locate_custom_file

# ---------------------------------------------------------------
# because I can
# ---------------------------------------------------------------
marks_banner() {
   echo "${MYNAME} - (c)Mark Dickinson 2004-2020"
   echo "Security auditing toolkit version ${PROCESSING_VERSION}"
} # end of marks_banner

# ---------------------------------------------------------------
# Are we adding additional users that may own SYSTEM class files
# If additional users are to be added to that list do that here
# and update the global SYSTEM_FILE_OWNERS variable.
# ---------------------------------------------------------------
update_system_file_owner_list() {
   hostid="$1"
   # Space seperated list of users that can own files of class SYSTEM.
   # Additional users can be added on a per server basis from the server
   # customisation file with ADD_SYSTEM_FILE_OWNER=xx
   SYSTEM_FILE_OWNERS="root bin lp abrt chrony ntp apache snort puppet mysql"
   if [ "${CUSTOMFILE}." != "." ];
   then
      echo "${SYSTEM_FILE_OWNERS}" > ${WORKDIR}/delme
      grep "^ADD_SYSTEM_FILE_OWNER=" ${CUSTOMFILE} | awk -F\= '{print $2}' | while read newowner
      do
         SYSTEM_FILE_OWNERS="${SYSTEM_FILE_OWNERS} ${newowner}"
         echo "${SYSTEM_FILE_OWNERS}" > ${WORKDIR}/delme
      done
      SYSTEM_FILE_OWNERS=`cat ${WORKDIR}/delme`
      rm -f ${WORKDIR}/delme
      echo "Note: System file owners updated to be ${SYSTEM_FILE_OWNERS} by config file"
   fi
} # end of update_system_file_owner_list

# ---------------------------------------------------------------
# Used to check file permissions, we do a lot of that.
# Input is from a ls -la with the expected owner appended
#
# hostid is only passed from the home dir checks as a
# general rule.
# If a config override file exists for ALL or the hostid then
# then check for root as an allowed owner and 755 as an
# allowed permission.
# This is kept seperate from the normal check_file_perms
# as we don't want all the file grepping involved here
# to be done for every file permission check.
# ---------------------------------------------------------------
check_homedir_perms() {
   databuffer="$1"
   reqd_permMask="$2"
   hostid="$3"
   # USE AWK, cut doesn't handle the tabs in the dataline
   perm=`echo "${databuffer}" | awk {'print $1'}`
   perm="${perm:0:10}"     # the pesky trailing . os selinux context again
   realowner=`echo "${databuffer}" | awk {'print $3'}`
   tempvar=`echo "${databuffer}" | awk -F\= {'print $2'}`
   neededowner=`echo "${tempvar}" | awk {'print $1'}`
   permlen="10"  # file & dir perms are 10 bytes
   PERM_CHECK_RESULT="OK"
   saveperm="${perm}"   # save it, we trash it in the loop below BUT need it later also
   # substring through the stings comparing them
   # An X in the match may be any permission, otherwise match exact
   if [ "${#reqd_permMask}." == "${permlen}." ];
   then
      while [ ${permlen} -gt 0 ]
      do
         test1=${perm:0:1}
         test2=${reqd_permMask:0:1}
         if [ "${test1}." != "${test2}." ];
         then
            if [ "${test2}." != "X." ];
            then
               PERM_CHECK_RESULT="Bad Permissions"
            fi
         fi
         perm=${perm:1:${#perm}}
         reqd_permMask=${reqd_permMask:1:${#reqd_permMask}}
         permlen=$((${permlen} - 1))
      done
   else
      echo "WARN: Bad check perm request (${reqd_permMask}) : ${databuffer}"
   fi
   # If insecure perms see if any of the system combinations is allowed
   # and after that check for any forced override
   if [ "${PERM_CHECK_RESULT}." != "OK." ];
   then
       # We MUST have a custom file for override checks
       if [ "${CUSTOMFILE}." != "." ];
       then
          dirname=`echo "${databuffer}" | awk {'print $9'}`
          dirname=`echo "${dirname}" | awk -F\= {'print $1'}`
          testvar=`grep "^ALLOW_DIRPERM_SYSTEM=${dirname}" ${CUSTOMFILE}`
          if [ "${testvar}." != "." ];
          then
             testperm=${saveperm:0:10}
             if [ "${testperm}." == "drwxr-xr-x." -o "${testperm}." == "drwxr-x--x." -o "${testperm}." == "drwx--x--x." -o "${testperm}." == "dr-xr-xr-x." -o "${testperm}." == "dr-xr-x---." -o "${testperm}." == "drwxr-x---." ];
             then
                PERM_CHECK_RESULT="OK"
             fi
          # else No custom file entry so leave as is
          fi
          # Not a valid system perm override, see if a specific dir override
          if [ "${PERM_CHECK_RESULT}." != "OK." ];
          then
             # added 'tail -1' as if a custom file replicated entries the check here fails as two lines <> one line
             testvar=`grep "^ALLOW_DIRPERM_EXPLICIT=${dirname}" ${CUSTOMFILE} | tail -1`
             if [ "${testvar}." != "." ];
             then
                testvar=`echo "${testvar}" | awk -F\= {'print $2'} | awk {'print $2'}`
                if [ "${saveperm}." == "${testvar}." ];
                then
                   PERM_CHECK_RESULT="OK"
                fi
             # else No custom file entry so leave as is
             fi
          fi
       # else No custom file so leave as is
       fi
   fi

   # And the ownership check
   if [ "${neededowner}." != "NA." ];
   then
      if [ "${neededowner}." != "SYSTEM." ];
      then
         if [ "${realowner}." != "${neededowner}." ];
         then
            # Can ownership be overridden to root, check the custom file
            if [ "${CUSTOMFILE}." != "." ];
            then
               dirname=`echo "${databuffer}" | awk {'print $9'}`
               dirname=`echo "${dirname}" | awk -F\= {'print $1'}`
               testvar=`grep "^ALLOW_OWNER_ROOT=${dirname}" ${CUSTOMFILE}`
            else 
               testvar=""
            fi
            if [ "${testvar}." == "." ];
            then
               # Original processing, an error
               if [ "${PERM_CHECK_RESULT}." == "OK." ];
               then
                  PERM_CHECK_RESULT="Bad Ownership ${realowner}, should be ${neededowner}"
               else
                  PERM_CHECK_RESULT="${PERM_CHECK_RESULT}<br>Bad Ownership ${realowner}, should be ${neededowner}"
               fi
            else
               # Owner is allowed to be root
               if [ "${realowner}." != "root." ];
               then
                  if [ "${PERM_CHECK_RESULT}." == "OK." ];
                  then
                     PERM_CHECK_RESULT="Bad Ownership ${realowner}, should be ${neededowner} or root"
                  else
                     PERM_CHECK_RESULT="${PERM_CHECK_RESULT}<br>Bad Ownership ${realowner}, should be ${neededowner} or root"
                  fi
               fi
            fi
         fi
      else  # System ownership checks
         # test a list of users allowed to own system files here first
         testvar=`echo "${SYSTEM_FILE_OWNERS}" | grep -w "${realowner}"`
         if [ "${testvar}." == "." ];
         then
            if [ "${PERM_CHECK_RESULT}." == "OK." ];
            then
               PERM_CHECK_RESULT="Bad Ownership"
            else
               PERM_CHECK_RESULT="${PERM_CHECK_RESULT}<br>Bad Ownership ${realowner}, should be ${neededowner}"
            fi
         # else is ok as was in the system user list
         fi
      fi
   fi
} # check_homedir_perms

# ---------------------------------------------------------------
# Used to check file permissions, we do a lot of that.
# Input is from a ls -la with the expected owner appended
#
# hostid is only passed from the home dir checks as a
# general rule.
# If a config override file exists for ALL or the hostid then
# ---------------------------------------------------------------
check_file_perms() {
   databuffer="$1"
   reqd_permMask="$2"
   # USE AWK, cut doesn't handle the tabs in the dataline
   perm=`echo "${databuffer}" | awk {'print $1'}`
   perm=${perm:0:10}   # fix for trailing . on perms now
   reqd_permMask=${reqd_permMask:0:10}   # in case passed in mask also
   realowner=`echo "${databuffer}" | awk {'print $3'}`
   # now processed as ls output=owner optdata
   tempvar=`echo "${databuffer}" | awk -F\= {'print $2'}`
   neededowner=`echo "${tempvar}" | awk {'print $1'}`
   permlen="10"  # file & dir perms are 10 bytes
   PERM_CHECK_RESULT="OK"
   # substring through the stings comparing them
   # An X in the match may be any permission, otherwise match exact
   if [ "${#reqd_permMask}." == "${permlen}." ];
   then
      while [ ${permlen} -gt 0 ]
      do
         test1=${perm:0:1}
         test2=${reqd_permMask:0:1}
         if [ "${test1}." != "${test2}." ];
         then
            if [ "${test2}." != "X." ];
            then
               if [ "${CUSTOMFILE}." != "." ];
               then
                  # See if we have a FORCE_PERM_OK for this file
                  thefilename=`echo "${databuffer}" | awk -F\= {'print $1'} | awk {'print $9'}`
                  testvar=`grep "^FORCE_PERM_OK=${thefilename}" ${CUSTOMFILE}`
                  if [ "${testvar}." == "." ];
                  then
                     PERM_CHECK_RESULT="Bad Permissions"
                  fi
               else
                  PERM_CHECK_RESULT="Bad Permissions"
               fi
            fi
         fi
         perm=${perm:1:${#perm}}
         reqd_permMask=${reqd_permMask:1:${#reqd_permMask}}
         permlen=$((${permlen} - 1))
      done
      # the below check should really be embedded in the if chains above
      # but is was getting too messy so add this newly created check here
      # If a file fails checks we see if there is an explicit permission
      # for this filename under any path (added for dynamically generated
      # pci bus filenames under fedora).
      if [ "${PERM_CHECK_RESULT}." != "OK." -a "${CUSTOMFILE}." != "." ];
      then
         thefilename=`echo "${databuffer}" | awk -F\= {'print $1'} | awk {'print $9'}`
         thefilename=`basename "${thefilename}"`
         testvar=`grep "^FORCE_ANYFILE_OK=${thefilename}" ${CUSTOMFILE}`
         if [ "${testvar}." != "." ];
         then
            perm=`echo "${databuffer}" | awk {'print $1'}`
            perm=${perm:0:10}   # fix for trailing . on perms now
            allowperm=`echo "${testvar}" | awk {'print $2'}`
            if [ "${perm}." == "${allowperm}." ];
            then
               PERM_CHECK_RESULT="OK"
            fi
         fi
      fi
   else
      echo "WARN: Bad check perm request (${reqd_permMask}) : ${databuffer}"
   fi
   # And the ownership check
   if [ "${neededowner}." != "NA." ];
   then
      if [ "${neededowner}." != "SYSTEM." ];
      then
         if [ "${realowner}." != "${neededowner}." ];
         then
            # Original processing, an error
            if [ "${PERM_CHECK_RESULT}." == "OK." ];
            then
               PERM_CHECK_RESULT="Bad Ownership ${realowner}, should be ${neededowner}"
            else
               PERM_CHECK_RESULT="${PERM_CHECK_RESULT}<br>Bad Ownership ${realowner}, should be ${neededowner}"
            fi
         fi
      else  # System ownership checks
         testvar=`echo "${SYSTEM_FILE_OWNERS}" | grep -w "${realowner}"`
         if [ "${testvar}." == "." ];
         then
            # check for a pecific override for this file
            testuser=""
            if [ "${CUSTOMFILE}." != "." ];
            then
               # See if we have a FORCE_OWNER_OK for this file
               thefilename=`echo "${databuffer}" | awk -F\= {'print $2'}`
               thefilename=`echo "${thefilename}" | awk {'print $9'}`
               testuser=`grep "^FORCE_OWNER_OK=${thefilename}" ${CUSTOMFILE}`
            fi
            if [ "${PERM_CHECK_RESULT}." == "OK." -a "${testuser}." == "."  ];
            then
               PERM_CHECK_RESULT="Bad Ownership"
            else
               if [ "${testuser}." == "." ];
               then
                  PERM_CHECK_RESULT="${PERM_CHECK_RESULT}<br>Bad Ownership ${realowner}, should be ${neededowner}"
               fi
            fi
         fi
      fi
   fi
} # check_file_perms

# ------------------------------------------------------------------------
# We collect server hardware details now, so make them available also.
# ------------------------------------------------------------------------
hwprof_line() {
   hostid="$1"
   echo "<br><br><center><a href=\"hwprof.html\">[ SERVER HARDWARE DETAILS ]</a></center><br><br>" >> ${RESULTS_DIR}/${hostid}/index.html
} # hwprof_line

hwprof_build() {
   hostid="$1"
   log_message ".     Building hardware profile page"
   cat << EOF > ${RESULTS_DIR}/${hostid}/hwprof.html
<html><head><title>Hardware details for server ${hostid}</title></head>
<body>
<h1>Hardware details for server ${hostid}</h1>
<pre><code>
EOF
cat ${SRCDIR}/hwinfo_${hostid}.txt >> ${RESULTS_DIR}/${hostid}/hwprof.html
   cat << EOF >> ${RESULTS_DIR}/${hostid}/hwprof.html
</code></pre>
</body></html>
EOF
} # hwprof_build

# ------------------------------------------------------------------------
# Work with individual server index report files, everything written
# here belongs under the server directory itself.
# ------------------------------------------------------------------------
server_index_start() {
   hostid="$1"
   echo "<html><head><title>Report Summary for server ${hostid}</title></head><body>" >> ${RESULTS_DIR}/${hostid}/index.html
   echo "<h1>Report Summary for server ${hostid}</h1>" >> ${RESULTS_DIR}/${hostid}/index.html
   write_key_server_info ${hostid}
   echo "<center><table border=\"1\" bgcolor=\"${colour_banner}\">" >> ${RESULTS_DIR}/${hostid}/index.html
   echo "<tr bgcolor=\"${colour_banner}\"><td>Appendix Name</td><td>Alerts</td><td>Warnings</td></tr>" >> ${RESULTS_DIR}/${hostid}/index.html
} # server_index_start

server_index_end() {
   hostid="$1"
   alerts=`cat ${RESULTS_DIR}/${hostid}/alert_totals`
   warns=`cat ${RESULTS_DIR}/${hostid}/warning_totals`
   echo "<tr><td>TOTALS</td><td>${alerts}</td><td>${warns}</td></tr>" >> ${RESULTS_DIR}/${hostid}/index.html
   echo "</table></center>" >> ${RESULTS_DIR}/${hostid}/index.html
   # 2010/09/22 Add the hardware profile list here for now
   hwprof_line "${hostid}"
   # And resume origional code
   echo "<br><br><center><a href=\"../index.html\">[ Back to main index ]</a></center><br><br>" >> ${RESULTS_DIR}/${hostid}/index.html
   echo "</body></html>" >> ${RESULTS_DIR}/${hostid}/index.html
} # server_index_end

server_index_addline() {
   hostid="$1"
   desc="$2"
   htmllink="$3"
   htmllink=`basename ${htmllink}`
   alerts=`cat ${RESULTS_DIR}/${hostid}/alert_count`
   warns=`cat ${RESULTS_DIR}/${hostid}/warning_count`
   groupsuppress=`cat ${RESULTS_DIR}/${hostid}/groupsuppress_count`
   add_to_counter "${hostid}" alert_totals ${alerts}
   add_to_counter "${hostid}" warning_totals ${warns}
   clear_counter "${hostid}" alert_count
   clear_counter "${hostid}" warning_count
   clear_counter "${hostid}" groupsuppress_count
   colour_to_use=${colour_OK}
   if [ ${warns} -gt 0 ];
   then
      colour_to_use=${colour_warn}
   fi
   if [ ${alerts} -gt 0 ];
   then
      colour_to_use=${colour_alert}
   fi
   echo "<tr bgcolor=\"${colour_to_use}\"><td><a href=\"${htmllink}\">${desc}</a>" >> ${RESULTS_DIR}/${hostid}/index.html
   echo "</td><td>${alerts}</td><td>${warns}</td></tr>" >> ${RESULTS_DIR}/${hostid}/index.html
} # server_index_addline

write_key_server_info() {
   hostid="$1"
   targetfile="${RESULTS_DIR}/${hostid}/index.html"
   echo "<center><table border=\"2\" bgcolor=\"${colour_banner}\">" >> ${targetfile}
   grep "^TITLE_" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
      titlekey=`echo "${dataline}" | cut -d_ -f2`
      titledata=`echo "${titlekey}" | cut -d\= -f2`
      titlekey=`echo "${titlekey}" | cut -d\= -f1`
      echo "<tr><td>${titlekey}</td><td>${titledata}</td></tr>" >> ${targetfile}
   done
   echo "<tr><td>ProcessVersion</td><td>${PROCESSING_VERSION}</td></tr>" >> ${targetfile}
   echo "</table></center><br><br>" >> ${targetfile}
} # write_key_info

write_details_page_exit() {
   hostid="$1"
   htmlfile="$2"
   echo "<br><br><center><a href=\"index.html\">[ Back to ${hostid} index ]</a>" >> ${htmlfile}
   echo "&nbsp&nbsp<a href=\"../index.html\">[ Back to Main index page ]</a>" >> ${htmlfile}
   echo "</center><br><br></body></html>" >> ${htmlfile}
} # write_details_page_exit

# ----------------------------------------------------------
#                      Appendix A.
#   A. Users
#      A.1 - Check users all have unique uids
#      A.2 - must have a password (check against shadow entries)
#      A.3 - home directories must be secure, and must exist
#      A.4 - check users against ftpuser deny entries, no system users should be omitted
#            (yes, A.3 should be in B.3, but we need the files from A so 'so be it'.
#      A.5 - /etc/shadow must be tightly secured
#      A.6 - Check system default passwd maxage, minlen etc
# ----------------------------------------------------------

extract_appendix_a_files() {
   hostid="$1"
   # password file entries
   grep "^PASSWD_FILE" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
	 echo "${realdata}" >> ${WORKDIR}/passwd
   done
   grep "^PASSWD_SHADOW_FILE" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo ":${realdata}" >> ${WORKDIR}/shadow  # : in front so searched can be unique
   done
   grep "^FTPUSERS_FILE" ${SRCDIR}/secaudit_${hostid}.txt | grep -v "^FTPUSERS_FILE.#" | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo ":${realdata}:" >> ${WORKDIR}/ftpusers
   done
   grep "^PERM_HOME_DIR" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | awk -F\= {'print $2"="$3'}`
     echo "${realdata}" >> ${WORKDIR}/home_dir_perms
   done
   grep "^LOGIN_DEFS" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/login.defs
   done
} # extract_appendix_a_files

pwconv_note() {
   echo "<p>The <b>pwconv</b> utility can be used to put the /etc/passwd and" > ${WORKDIR}/pwconv_note
   echo "/etc/shadow files back into sycronisation. You should use this to" >> ${WORKDIR}/pwconv_note
   echo "resolve the issues found between these two files.</p>" >> ${WORKDIR}/pwconv_note
} # pwconv_note

build_appendix_a() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_A.html"
   log_message ".     Building Appendix A - performing user validation checks"

   echo "<html><head><title>User Valdidation Checks for ${hostid}</title></head><body>" >> ${htmlfile}
   echo "<h1>Appendix A - User Validation Checks for ${hostid}</h1>" >> ${htmlfile}

   extract_appendix_a_files ${hostid}

   # 1. Check users all have unique uids
   echo "<h2>A.1 User Unique UID Checks</h2>" >> ${htmlfile}
   echo "<p>All users must have a unique uid. This prevents inadvertant" >> ${htmlfile}
   echo "access to other users (or system) files.</p>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   lastfound=""
   cat ${WORKDIR}/passwd | cut -d: -f3 | sort | while read dataline
   do
      if [ "${dataline}." == "${lastfound}." ];
      then
         echo "${dataline}" >> ${WORKDIR}/duplicate_uid
      fi
	  lastfound="${dataline}"
   done
   if [ -f ${WORKDIR}/duplicate_uid ];
   then
      cat ${WORKDIR}/duplicate_uid | uniq | while read dataline
      do
	     echo "<table bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
         echo "More than one user has uid ${dataline}<ul>"
         inc_counter ${hostid} alert_count
         cat ${WORKDIR}/passwd | while read pswdline
         do
            testvar=`echo "${pswdline}" | cut -d: -f3`
            if [ "${testvar}." == "${dataline}." ];
            then
                echo "<li>${pswdline}</li>" >> ${htmlfile}
            fi
         done
         echo "</ul></td></tr></table>" >> ${htmlfile}
      done
      delete_file ${WORKDIR}/duplicate_uid
      echo "<p>Duplicate UID numbers were found in the /etc/passwd file." > ${WORKDIR}/uid_note
      echo "This is a risk becuase if users share UIDs they share ownership" >> ${WORKDIR}/uid_note
      echo "of files and directories. This practise is dangerous, and <b>the" >> ${WORKDIR}/uid_note
      echo "UID 0</b> must never be shared as this is root priviledge.<br>" >> ${WORKDIR}/uid_note
      echo "To resolve these issues use userdel/useradd to delete the users" >> ${WORKDIR}/uid_note
      echo "and re-add them with a different UID. You should also give" >> ${WORKDIR}/uid_note
      echo "ownership of all the files in their home directory to the new" >> ${WORKDIR}/uid_note
      echo "UID you have allocated.<br>If users must share files place them" >> ${WORKDIR}/uid_note
      echo "in the same group and manage it via group access permissions.</p>" >> ${WORKDIR}/uid_note
   fi
   if [ -f ${WORKDIR}/${hostid}_all_ok ];
   then
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
      echo "<p>No problems were found with user uid checks</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
   fi

   # 2. Check users against shadow file to ensure they have a password
   echo "<h2>A.2 User Password Checks</h2>" >> ${htmlfile}
   echo "<p>All users must either have a password, or have the account" >> ${htmlfile}
   echo "locked out.</p>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   # Check every user in passwd is in the shadow file with a password
   cat ${WORKDIR}/passwd | while read dataline
   do
      userid=`echo "${dataline}" | cut -d: -f1`
      # must exist in shadow file
      testvar=`grep ":${userid}:" ${WORKDIR}/shadow`
      testvar=`echo "${testvar}" | cut -d: -f2`
      if [ "${testvar}." != "${userid}." ]
      then
	     echo "<table bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
         echo "User <b>${userid}</b> has no entry in /etc/shadow, run pwconv<br>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
         pwconv_note
         inc_counter ${hostid} alert_count
      else
         # must have a password, check expiry
         # * is=locked ?, x=locked ?, !!=locked,no initial passwd set ?, else pswd assumed
         shadpswdflag=`echo "${testvar}" | cut -d: -f2`
         changed_daysago=`echo "${testvar}" | cut -d: -f3` # days from Jan1 1970 it last changed (seems to be not used?)
         change_every_Ndays=`echo "${testvar}" | cut -d: -f5`
         # Too many assumptions ?, probably check users with passwords only for now
         if [ "${shadpswdflag}." == "*." ];
         then
            shadpswdflag="-"   # to stop case * trigger
         fi
         case "${shadpswdflag}" in
         "-" | "x" | "!!" ) ;;   # no check required or wanted
         *)  # normal entry, check
            if [ "${change_every_Ndays}." == "99999." ];
            then
	              echo "<table bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
                  echo "User <b>${userid}</b> has a password that never expires<br>" >> ${htmlfile}
                  echo "</td></tr></table>" >> ${htmlfile}
                  inc_counter ${hostid} warning_count
            fi
            ;;
         esac
      fi
   done
   # check every user in the shadow file exists in the passwd file
   cat ${WORKDIR}/shadow | while read dataline
   do
      userid=`echo "${dataline}" | cut -d: -f2`
      # must exist in passwd file
      testvar=`grep "${userid}:" ${WORKDIR}/passwd`
      if [ "${testvar}." == "." ];
      then
         echo "<table bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
         echo "Shadow file entry for user <b>${userid}</b>, but no passwd file entry, run pwconv" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
         inc_counter ${hostid} alert_count
         pwconv_note
      fi
   done
   # Explainations needed ?
   if [ -f ${WORKDIR}/pwconv_note ];
   then
      cat ${WORKDIR}/pwconv_note >> ${htmlfile}
      rm -f ${WORKDIR}/pwconv_note
   fi
   if [ -f ${WORKDIR}/${hostid}_all_ok ];
   then
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
      echo "<p>No problems were found with user password checks</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
   fi

   # 3. Check the home directories are secure
   echo "<h2>A.3 User Home Directory Checks</h2>" >> ${htmlfile}
   echo "<p>User home directories need to be secured tightly to" >> ${htmlfile}
   echo "prevent other users from inadvertently viewing or" >> ${htmlfile}
   echo "modifying personal user files.</p>" >> ${htmlfile}
   echo "<p>The only exception to this should be system directories" >> ${htmlfile}
   echo "such as sbin that are the home directory for multiple" >> ${htmlfile}
   echo "system userids, or contain program files that other users" >> ${htmlfile}
   echo "are expected to require. These exceptions are managed from" >> ${htmlfile}
   echo "the server customisation files as required.</p>" >> ${htmlfile}
   echo "<p>This section also reports on user entries that are configured with home directories that do not exist." >> ${htmlfile}
   echo "That does not necessarily indicate a problem as some system accounts are setup that way" >> ${htmlfile}
   echo "so missing home directories are logged as warnings, but you should check them.</p>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   echo "<table border=\"1\"><tr bgcolor=\"${colour_banner}\"><td>User Name</td><td>Problem identified</td></tr>" >> ${htmlfile}
   cat ${WORKDIR}/home_dir_perms | while read dataline
   do
      # Use AWK, cut doesn't handle tabs in the data
      permdata=`echo "${dataline}" | awk {'print $1'}`
      # FIX: since FC12 (FC11???) directory perms have a . appended to
      #      show they are selinux managed, which breaks the checks.
      #      explicitly only use the dir perms
      permdata=${permdata:0:10}
      # use 2 at the end of each var or they are overwritten by procs we call
      dirname2=`echo "${dataline}" | awk {'print $9'}`
      dirname2=`echo "${dirname2}" | awk -F\= {'print $1'}`
      username2=`echo "${dataline}" | awk -F\= {'print $2'}`
      username2=`echo "${username2}" | awk {'print $1'}`
      if [ "${permdata}." == "MISSING." ];
      then
         # home directory does not exist
         echo "<tr bgcolor=\"${colour_warn}\"><td>${username2}</td><td>The home directory for <b>${username2}</b> does not exist (${dirname2})</td></tr>" >> ${htmlfile}
         inc_counter ${hostid} warning_count
      else
         check_homedir_perms "${dataline}" "drXx------" "${hostid}"
         if [ "${PERM_CHECK_RESULT}." != "OK." ]; # if not empty has error text
         then
            echo "<tr bgcolor=\"${colour_alert}\"><td>${username2}</td>" >> ${htmlfile}
            echo "<td>The home directory of <b>${username2}</b> is secured incorrectly (${dirname2})" >> ${htmlfile}
            echo "<br>${PERM_CHECK_RESULT}: ${dataline}</td></tr>" >> ${htmlfile}
            inc_counter ${hostid} alert_count
         fi
      fi
   done
   if [ -f ${WORKDIR}/${hostid}_all_ok ];
   then
      echo "<tr bgcolor=\"${colour_OK}\"><td>N/A</td><td>No problems were found with user home directory permission checks</td></tr>" >> ${htmlfile}
   fi
   echo "</table>" >> ${htmlfile}

   # 4. Check the ftpusers deny file against the passwd file
   echo "<h2>A.4 FTP User Access Checks</h2>" >> ${htmlfile}
   echo "<h3>A.4.1 Who can use ftp</h3>" >> ${htmlfile}
   echo "<p>FTP users have the ability to change, delete and retreive information" >> ${htmlfile}
   echo "that may be sensitive or critical to the server. The users who are" >> ${htmlfile}
   echo "permitted to use FTP need to be reviewed frequently.</p>" >> ${htmlfile}
   echo "" >> ${htmlfile}
   echo "" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   if [ ! -f ${WORKDIR}/ftpusers ];
   then
      echo "<table bgcolor=\"${colour_alert}\" width=\"100%\"><tr><td>" >> ${htmlfile}
	  echo "<p>No <b>/etc/ftpusers</b> file exists on the server. This means" >> ${htmlfile}
	  echo "all users are able to use <b>ftp</b></p>." >> ${htmlfile}
	  echo "<p><b>Remedial action:</b> create a <b>/etc/ftpusers</b> file and" >> ${htmlfile}
	  echo "add an entry for every system user (ie: uucp, news etc) as they" >> ${htmlfile}
	  echo "should not be permitted to use ftp.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
      inc_counter ${hostid} alert_count
   else
      cat ${WORKDIR}/passwd | while read dataline
      do
         username=`echo "${dataline}" | cut -d: -f1`
         testvar=`grep ":${username}:" ${WORKDIR}/ftpusers`
         if [ "${testvar}." == "." ];
         then
            echo "${username}" >> ${WORKDIR}/ftp_allowed
         fi
      done
      if [ -f ${WORKDIR}/ftp_allowed ];
      then
         echo "<p>The users listed here can use ftp, and need to be reviewed. Please" >> ${htmlfile}
         echo "review these userids to ensure that they still require access" >> ${htmlfile}
         echo "to ftp Investigate replacing ftp with scp for internal use.</p>" >> ${htmlfile}
         echo "<table border=\"1\" bgcolor=\"${colour_warn}\" width=\"100%\"><tr><td>" >> ${htmlfile}
         echo "<b><pre>" >> ${htmlfile}
         cat ${WORKDIR}/ftp_allowed >> ${htmlfile}
         echo "</pre></b>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
         rm -f ${WORKDIR}/ftp_allowed
         inc_counter ${hostid} warning_count
      else
         echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
		 echo "<p>No problems found. The /etc/ftpusers file blocks all users from ftp.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
      fi

      # Step 2, scan the ftpusers file, report any entries NOT in passwd file
      echo "<h3>A.4.2 Check for inconsistencies in ftpusers</h3>" >> ${htmlfile}
      echo "<p>Many sysadmins forget to remove a user from /etc/ftpusers when it is removed from" >> ${htmlfile}
	  echo "the password file. This section checks for that occurence.</p>" >> ${htmlfile}
      cat ${WORKDIR}/ftpusers | while read dataline
      do
         username=`echo "${dataline}" | cut -d: -f2`
         testvar=`grep "${username}:" ${WORKDIR}/passwd`
         if [ "${testvar}." == "." ];
         then
            echo "${username}" >> ${WORKDIR}/ftp_userentry_missing
         fi
      done
      if [ -f ${WORKDIR}/ftp_userentry_missing ];
      then
         echo "<p><b>These users are in /etc/ftpusers but NOT in /etc/passwd</b></p>" >> ${htmlfile}
         echo "<p>You have not been removing users from" >> ${htmlfile}
         echo "the /etc/ftpusers file when you remove them from the system" >> ${htmlfile}
         echo "passwd file. Review your user deletion procedures, and clean" >> ${htmlfile}
         echo "up the /etc/ftpusers file.</p>" >> ${htmlfile}
         echo "<table border=\"1\" bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
         echo "<b><pre>" >> ${htmlfile}
         cat ${WORKDIR}/ftp_userentry_missing >> ${htmlfile}
         echo "</pre></b>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
         rm -f ${WORKDIR}/ftp_userentry_missing
         inc_counter ${hostid} alert_count
      else
         echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
         echo "<p>No inconsistencies found. All users in /etc/ftpusers also exist in the /etc/passwd file.</p>" >> ${htmlfile}
		 echo "</td></tr></table>" >> ${htmlfile}
      fi
   fi  # if ftpusers file exists

   # Need to write a happy message ?
#   if [ -f ${WORKDIR}/${hostid}_all_ok ];
#   then
#      echo "<p>No problems were found with FTP access checks</p>" >> ${htmlfile}
#   fi

   # 5 - /etc/shadow must be tightly secured
   echo "<h3>A.5 Shadow file security</h3>" >> ${htmlfile}
   echo "<p>The /etc/shadow file mist be tightle secured. This file" >> ${htmlfile}
   echo "should only ever be updated by system utilities.</p>" >> ${htmlfile}
   testvar=`grep "^PERM_SHADOW_FILE" ${SRCDIR}/secaudit_${hostid}.txt | awk -F\= {'print $2'}`
   shadowperms=`echo "${testvar}" | awk '{print $1'}`
   if [ "${shadowperms}." != "----------.." -a "${shadowperms}." != "-r--------.." ];
   then
      echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
      echo "<p>The /etc/shadow file is badly secured. <b>It should be -r-------- or ---------- and owned by root</b>.<br>" >> ${htmlfile}
      echo "Actual: ${testvar}<br>" >> ${htmlfile}
      echo "${PERM_CHECK_RESULT}." >> ${htmlfile}
      echo "Log up to root and resecure this file correctly <b>immediately</b>.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
      inc_counter ${hostid} alert_count
   else
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
      echo "<p>The /etc/shadow file is correctly secured, no action needed.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
   fi

   # 6 - Check system default passwd maxage, minlen etc
   if [ -f ${WORKDIR}/login.defs ];      # check, added later so not in all collection releases
   then
      echo "<h3>A.6 User default attributes file</h3>" >> ${htmlfile}
	  echo "<p>The default attributes used when adding a new user need to be set to" >> ${htmlfile}
	  echo "reasonable values, the defaults are generally unaceptable. These are" >> ${htmlfile}
	  echo "the values in /etc/login.defs for server ${hostid}.</p>" >> ${htmlfile}
      # Get and ensure values exist for the data being checked
      maxdays=`grep "^PASS_MAX_DAYS" ${WORKDIR}/login.defs | awk {'print $2'}`
      mindays=`grep "^PASS_MIN_DAYS" ${WORKDIR}/login.defs | awk {'print $2'}`
      minlen=`grep "^PASS_MIN_LEN" ${WORKDIR}/login.defs | awk {'print $2'}`
      warndays=`grep "^PASS_WARN_AGE" ${WORKDIR}/login.defs | awk {'print $2'}`
      if [ "${maxdays}." == "." ];
      then
         maxdays="0"
      fi
      if [ "${mindays}." == "." ];
      then
         mindays="0"
      fi
      if [ "${minlen}." == "." ];
      then
         minlen="0"
      fi
      if [ "${warndays}." == "." ];
      then
         warndays="0"
      fi
      # Check it
	  echo "<table border=\"1\"><tr bgcolor=\"${colour_border}\"><td><center>User Default Settings</center></td></tr>" >> ${htmlfile}
      if [ ${maxdays} -gt 31 ];  # doesn't expire in 31 days as a default
      then
         echo "<tr bgcolor=\"${colour_alert}\"><td>Default password expiry > 31 days, it is ${maxdays}</td></tr>" >> ${htmlfile}
         inc_counter ${hostid} alert_count
      else
         echo "<tr bgcolor=\"${colour_OK}\"><td>Default password expiry is <= 31 days</td></tr>" >> ${htmlfile}
      fi
      if [ ${mindays} -gt 3 ];   # user can't change for over three days, too excessive
      then
         echo "<tr bgcolor=\"${colour_warn}\"><td>By default users cannot change passwords for ${mindays}, too excesive</td></tr>" >> ${htmlfile}
         inc_counter ${hostid} warning_count
      else
         echo "<tr bgcolor=\"${colour_OK}\"><td>The default time within which users can change passwords is acceptable</td></tr>" >> ${htmlfile}
      fi
      if [ ${minlen} -lt 6 ];    # passwds less than 6 is a bad default
      then
         echo "<tr bgcolor=\"${colour_alert}\"><td>Default minimum password length < 6, it is ${minlen}</td></tr>" >> ${htmlfile}
         inc_counter ${hostid} alert_count
      else
         echo "<tr bgcolor=\"${colour_OK}\"><td>Default minimum password length is OK</td></tr>" >> ${htmlfile}
      fi
      if [ ${warndays} -lt 7 ];  # less than 7 days warning is insufficient
      then
         echo "<tr bgcolor=\"${colour_warn}\"><td>Default warning on password expiry is < 7 days</td></tr>" >> ${htmlfile}
         inc_counter ${hostid} warning_count
      else
         echo "<tr bgcolor=\"${colour_OK}\"><td>Default password expiry warning is >= 7 days, OK</td></tr>" >> ${htmlfile}
      fi
      echo "</table>" >> ${htmlfile}
   fi

   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"

   # Add a summary of the section to the server index, and total alert & warning counts
   server_index_addline "${hostid}" "Appendix A - User Checks" "${htmlfile}"
} # build_appendix_a

# ----------------------------------------------------------
#                      Appendix B.
#   B. Network access
#      B.1 - check system host equivalences files
#      B.2 - check user host equivalences files and security of
#      B.3 - check NFS file shares
#      B.4 - check SAMBA
# ----------------------------------------------------------

extract_appendix_b_files() {
   hostid="$1"
   clean_prev_work_files
   mkdir ${WORKDIR}

   # system host equivalence file entries
   grep "^PERM_HOSTS_EQIV_SYSTEM" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/system_equiv_files
   done
   # user host equivalence file entries
   grep "^PERM_HOSTS_EQIV_USER" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
	 echo "${realdata}" >> ${WORKDIR}/user_equiv_files
   done
} # extract_appendix_b_files

build_appendix_b() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_B.html"
   log_message ".     Building Appendix B - performing network access checks"

   echo "<html><head><title>User Valdidation Checks for ${hostid}</title></head><body>" >> ${htmlfile}
   echo "<h1>Appendix B - Network Access Checks for ${hostid}</h1>" >> ${htmlfile}

   extract_appendix_b_files ${hostid}

   echo "<h2>Appendix B.1 - System Host Equivalence Files</h2>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   if [ -f ${WORKDIR}/system_equiv_files ];
   then
       echo "<p>Server wide host equivalence files exist, the use of" >> ${htmlfile}
       echo "these is discouraged as they may provide unauthorised" >> ${htmlfile}
       echo "users with a gateway to this server. Review whether" >> ${htmlfile}
       echo "these files are really required on your server.</p>" >> ${htmlfile}
       echo "<table border=\"1\" bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
       echo "<pre>" >> ${htmlfile}
       cat ${WORKDIR}/system_equiv_files >> ${htmlfile}
       echo "</pre></table>" >> ${htmlfile}
       inc_counter ${hostid} alert_count
   fi
   if [ -f ${WORKDIR}/${hostid}_all_ok ];
   then
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
      echo "<p>No problems found. There are no system wide host equivalences files.</p>" >> ${htmlfile}
      echo "</pre></table>" >> ${htmlfile}
   fi

   echo "<h2>Appendix B.2 - User Host Equivalence Files</h2>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   if [ -f ${WORKDIR}/user_equiv_files ];
   then
       echo "<p>Some individual users on this server have their own" >> ${htmlfile}
       echo "<b>personal</b> host equivalence files. This can allow" >> ${htmlfile}
       echo "individual users to bypass security policies you may have" >> ${htmlfile}
       echo "in place for network access controls.</p>" >> ${htmlfile}
       echo "<p>Review these files and determine if the individual" >> ${htmlfile}
       echo "users should be permitted to use these files.</p>" >> ${htmlfile}
       echo "<table border=\"1\" bgcolor=\"${colour_alert}\"><tr><td>" >> ${htmlfile}
       echo "<pre>" >> ${htmlfile}
       cat ${WORKDIR}/system_equiv_files >> ${htmlfile}
       echo "</pre></table>" >> ${htmlfile}
       numentries=`cat ${WORKDIR}/system_equiv_files | wc -l`
       get_num_only ${numentries}
       add_to_counter_counter ${hostid} alert_count ${NUM_VALUE}
   fi
   if [ -f ${WORKDIR}/${hostid}_all_ok ];
   then
      echo "<p>No problems found. There are no personal user host equivalences files.</p>" >> ${htmlfile}
   fi

   echo "<h2>Appendix B.3 - NFS File Shares</h2>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   testvar=`grep "^PERM_ETC_EXPORTS" ${SRCDIR}/secaudit_${hostid}.txt | awk -F\= {'print $2"="$3'}`
   if [ "${testvar}." != "." ];
   then
      check_file_perms "${testvar}" "-rwXX--X--"
      if [ "${PERM_CHECK_RESULT}." != "OK." ]; # if not empty has error text
      then
         inc_counter ${hostid} alert_count
         echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
         echo "<p><b>The /etc/exports file is badly secured</b>. It must be owned by root and" >> ${htmlfile}
         echo "only writeable by root.<br>Actual: ${testvar}<br>${PERM_CHECK_RESULT}<br>" >> ${htmlfile}
         echo "Log up to root and resecure this file <b>immediately</b>.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
      fi
      # 2007/08/14 - added the grep -v to suprres comments as empty (only comments in file)
      #              were raising alerts. Done in processing not capture, the capture still
      #              needs to collect what was there.
      numentries=`grep "^ETC_EXPORTS_DATA" ${SRCDIR}/secaudit_${hostid}.txt | grep -v "^ETC_EXPORTS_DATA=#" | wc -l`
      get_num_only ${numentries}
      numentries=${NUM_VALUE}
      if [ "${numentries}." != "0." ];
      then
         echo "<p>The file /etc/exports exists. Check the exported directories to" >> ${htmlfile}
         echo "ensure they are still required as NFS mounts.</p>" >> ${htmlfile}
         echo "<table border=\"1\"><tr bgcolor=\"${colour_banner}\"><td>" >> ${htmlfile}
         echo "<center>/etc/exports file for ${hostid}</center></td></tr>" >> ${htmlfile}
         echo "<tr bgcolor=\"${colour_warn}\"><td><pre>" >> ${htmlfile}
         grep "^ETC_EXPORTS_DATA" ${SRCDIR}/secaudit_${hostid}.txt | cut -d\= -f2 | cat >> ${htmlfile}
         echo "</pre></td></tr></table>" >> ${htmlfile}
         inc_counter ${hostid} warning_count
      else
         echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
         echo "<p>The /etc/exports file exists, but is empty or has no uncommented entries. This is OK.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
      fi
   else
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
      echo "<p>No problems found. No /etc/exports file exists so no NFS file shares.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
   fi

   echo "<h2>Appendix B.4 - Samba file Shares</h2>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok
   testvar=`grep "^APPLICATION_SAMBA_RUNNING" ${SRCDIR}/secaudit_${hostid}.txt | cut -d\= -f2`
   if [ "${testvar}." == "YES." ];
   then
      echo "<table bgcolor=\"${colour_warn}\"><tr><td>" >> ${htmlfile}
      echo "<p>Samba or Netbios services were active on the server at the time the" >> ${htmlfile}
      echo "snapshot was taken. As customisation of this is site specific you need" >> ${htmlfile}
      echo "to manually check the server for possible loopholes.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
      inc_counter ${hostid} warning_count
   else
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
      echo "<p>Samba and Netbios Services were not running on the server at the time the snapshot" >> ${htmlfile}
      echo "was taken, so no remedial actions or checking are required.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
   fi

   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"

   # Add a summary of the section to the server index, and total alert & warning counts
   server_index_addline "${hostid}" "Appendix B - Network Access Checks" "${htmlfile}"
} # build_appendix_b

# ----------------------------------------------------------
#                      Appendix C.
#   C. Network Connectivity
#      C.1 - compare listening ports against allowed ports
#      C.2 - check services/portconf file for insecure applications ?
# ----------------------------------------------------------
extract_appendix_c_files() {
   hostid="$1"
   clean_prev_work_files
   mkdir ${WORKDIR}

   # ====== Ports listening for connections ======
   # ---- tcp ports open ----
   grep "^PORT_TCP_LISTENING" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/active_tcp_services
   done
   # A bit more work, more readable if they are sorted.
   cat ${WORKDIR}/active_tcp_services | while read dataline
   do
      # tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
      listenaddr=`echo "${dataline}" | awk {'print $4'}`
      listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
      listenaddr=`echo "${listenaddr}" | awk -F: {'print $1'}`
      echo "${listenport} ${listenaddr}" >> ${WORKDIR}/active_tcp_services.wrk
   done
   grep "^PORT_TCPV6_LISTENING" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/active_tcp_services6
   done
   cat ${WORKDIR}/active_tcp_services6 | while read dataline
   do
      # tcp6       0      0 :::443                  :::*                    LISTEN
      # tcp6       0      0 fe80::200b:90ff:fe4:123 :::* 
      listenaddr=`echo "${dataline}" | awk '{print $4'}`
      # the last field we know is the port, print the fieldcount field
      listenport=`echo "${listenaddr}" | awk -F: '{print $NF}'`
      listenaddr=`echo "${listenaddr} X" | sed -e"s/:$listenport X/:/g"`
      echo "${listenport} ${listenaddr}" >> ${WORKDIR}/active_tcp_services.wrk
   done
   cat ${WORKDIR}/active_tcp_services.wrk | sort -n > ${WORKDIR}/active_tcp_services.wrk2

   grep "^PORT_UDP_LISTENING" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/active_udp_services
   done
   # A bit more work, more readable if they are sorted.
   # Check here, these were added in a later release so may
   # not be provided by all collector scripts out there.
   if [ -f ${WORKDIR}/active_udp_services ];
   then
      cat ${WORKDIR}/active_udp_services | while read dataline
      do
         # udp        0      0 0.0.0.0:111             0.0.0.0:*
         listenaddr=`echo "${dataline}" | awk {'print $4'}`
         listenport=`echo "${listenaddr}" | awk -F: {'print $2'}`
         listenaddr=`echo "${listenaddr}" | awk -F: {'print $1'}`
         echo "${listenport} ${listenaddr}" >> ${WORKDIR}/active_udp_services.wrk
      done
   fi
   grep "^PORT_UDPV6_LISTENING" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/active_udp_services6
   done
   # A bit more work, more readable if they are sorted.
   # Check here, these were added in a later release so may
   # not be provided by all collector scripts out there.
   cat ${WORKDIR}/active_udp_services6 | while read dataline
   do
      # udp6       0      0 :::111                  :::*                               
      # udp6       0      0 fe80::200b:90ff:fe4:123 :::*                               
      # udp6       0      0 fe80::acc9:13ff:fed:123 :::*                               
      # udp6       0      0 fe80::5054:ff:fe38::123 :::*                               
      # udp6       0      0 fe80::42:26ff:fef1::123 :::* 
      # different number of : delimeters in addresses
      listenaddr=`echo "${dataline}" | awk '{print $4'}`
      #fieldcount=`echo "${workfield}" | awk -F: '{print NF}'`
      # the last field we know is the port, print the fieldcount field
      listenport=`echo "${listenaddr}" | awk -F: {'print $NF'}`
      listenaddr=`echo "${listenaddr} X" | sed -e"s/:$listenport X/:/g"`
      echo "${listenport} ${listenaddr}" >> ${WORKDIR}/active_udp_services.wrk
   done
   cat ${WORKDIR}/active_udp_services.wrk | sort -n > ${WORKDIR}/active_udp_services.wrk2

   # --- The unix ports open ---
   grep "^PORT_UNIX_LISTENING" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/active_unix_services
   done

   # ====== And other stuff needed ======
   # --- Extract The server services file for xref use ---
   grep "^SERVICES_FILE" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/services
   done

   # --- Build the allowed ports files if the override file exists ---
   override_file=""
   if [ -f ${OVERRIDES_DIR}/${hostid}.custom ];
   then
      override_file="${OVERRIDES_DIR}/${hostid}.custom"
   else
      if [ -f ${OVERRIDES_DIR}/ALL.custom ];
      then
         override_file="${OVERRIDES_DIR}/ALL.custom"
      fi
   fi
   if [ "${override_file}." != "." ];
   then
      grep "^TCP_PORT_ALLOWED" ${override_file} | cut -d\= -f2 | cat > ${WORKDIR}/allowed_tcp_ports
      grep "^UDP_PORT_ALLOWED" ${override_file} | cut -d\= -f2 | cat > ${WORKDIR}/allowed_udp_ports
   fi
} # extract_appendix_c_files

build_appendix_c() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_C.html"
   log_message ".     Building Appendix C - performing network connectivity checks"

   extract_appendix_c_files "${hostid}"

   echo "<html><head><title>Network Connectivity Checks for ${hostid}</title></head><body>" >> ${htmlfile}
   echo "<h1>Appendix C - Network Connectivity Checks for ${hostid}</h1>" >> ${htmlfile}

   echo "<p>This appendix lists all the open ports on the server, even" >> ${htmlfile}
   echo "if the ports are expected to be open you should review" >> ${htmlfile}
   echo "the ports in use to see if any can be closed.</p>" >> ${htmlfile}

   # C.1 Check all listening ports against the allowed services and the
   #    services files. Report allowed services as green fields, unexpected
   #    ones in red as alerts for review.
   #    Note: anything lstening on 0.0.0.0 rates a warning even if allowed
   #          as this can be attached to by all interfaces, even internet ones.
   #          Updated for tcp6 to also warn for ::: as well as 0.0.0.0
   #    Note2: there will always be something listening so don't bother
   #           checking if the file exists before creating the table headers here.
   echo "<h1>C.1.1 - TCP access ports open on the server</h1>" >> ${htmlfile}
   echo "<p>These are the open ports listening for incoming connections" >> ${htmlfile}
   echo "to this server. These need to be reviewed periodically.</p>" >> ${htmlfile}
   echo "<p>As a general rule services specifically allowed to run on" >> ${htmlfile}
   echo "the servers (as defined in custom file) will be green, unless they listen on all interfaces" >> ${htmlfile}
   echo "which rates them a warning. For all other ports that are listening" >> ${htmlfile}
   echo "you will get an alert as they are unexpected.</p>" >> ${htmlfile}
   echo "<table border=\"1\" bgcolor=\"${colour_banner}\" width=\"100%\"><tr><td colspan=\"3\"><center>TCP Ports open on the server</center></td></tr>" >> ${htmlfile}
   echo "<tr><td>Port</td><td>Listening address</td><td>Port description</td></tr>" >> ${htmlfile}
   cat ${WORKDIR}/active_tcp_services.wrk2 | while read dataline
   do
      # 80 0.0.0.0 
      listenaddr=`echo "${dataline}" | awk {'print $2'}`
      listenport=`echo "${dataline}" | awk {'print $1'}`
      if [ -f ${WORKDIR}/allowed_tcp_ports ];
      then
         allowed=`grep ":${listenport}:" ${WORKDIR}/allowed_tcp_ports`
      else
         allowed=""
      fi
      if [ "${allowed}." != "." ];  # found an allowed match
      then
         desc=`echo "${allowed}" | awk -F: {'print $3'}`
         if [ "${listenaddr}." == "0.0.0.0." -o "${listenaddr}." == ":::." ];
         then
            # make a warning colour
            echo "<tr bgcolor=\"${colour_warn}\"><td>${listenport}</td><td>${listenaddr}</td><td>${desc}</td></tr>" >> ${htmlfile}
            inc_counter ${hostid} warning_count
         else
            # make a green colour
            echo "<tr bgcolor=\"${colour_OK}\"><td>${listenport}</td><td>${listenaddr}</td><td>${desc}</td></tr>" >> ${htmlfile}
         fi
      else
         inc_counter ${hostid} alert_count
         portname=`grep -w "${listenport}.tcp" ${WORKDIR}/services` # Use -w for exact word match
         if [ "${portname}." == "." ];
         then
            desc="NOT DESCRIBED IN SERVICES FILE"
         else
            desc=`echo "${portname}" | awk {'print $2" "$3" "$4" "$5" "$6'}`
         fi
         # An unexpected port, all in red
         echo "<tr bgcolor=\"${colour_alert}\"><td>${listenport}</td><td>${listenaddr}</td><td>${desc}</td></tr>" >> ${htmlfile}
      fi
   done
   echo "</table>" >> ${htmlfile}

   # UDP Ports active
   echo "<br><br><table border=\"1\" bgcolor=\"${colour_banner}\" width=\"100%\"><tr><td colspan=\"3\"><center>UDP Ports open on the server</center></td></tr>" >> ${htmlfile}
   echo "<tr><td>Port</td><td>Listening address</td><td>Port description</td></tr>" >> ${htmlfile}
   cat ${WORKDIR}/active_udp_services.wrk2 | while read dataline
   do
      # 80 0.0.0.0
      listenaddr=`echo "${dataline}" | awk {'print $2'}`
      listenport=`echo "${dataline}" | awk {'print $1'}`
      if [ -f ${WORKDIR}/allowed_udp_ports ];
      then
         allowed=`grep ":${listenport}:" ${WORKDIR}/allowed_udp_ports`
      else
         allowed=""
      fi
      if [ "${allowed}." != "." ];  # found an allowed match
      then
         desc=`echo "${allowed}" | awk -F: {'print $3'}`
         if [ "${listenaddr}." == "0.0.0.0." -o "${listenaddr}." == ":::." ];
         then
            # make a warning colour
            echo "<tr bgcolor=\"${colour_warn}\"><td>${listenport}</td><td>${listenaddr}</td><td>${desc}</td></tr>" >> ${htmlfile}
            inc_counter ${hostid} warning_count
         else
            # make a green colour
            echo "<tr bgcolor=\"${colour_OK}\"><td>${listenport}</td><td>${listenaddr}</td><td>${desc}</td></tr>" >> ${htmlfile}
         fi
      else
         inc_counter ${hostid} alert_count
         portname=`grep -w "${listenport}.udp" ${WORKDIR}/services` # Use -w for exact word match
         if [ "${portname}." == "." ];
         then
            desc="NOT DESCRIBED IN SERVICES FILE"
         else
            desc=`echo "${portname}" | awk {'print $2" "$3" "$4" "$5" "$6'}`
         fi
         # An unexpected port, all in red
         echo "<tr bgcolor=\"${colour_alert}\"><td>${listenport}</td><td>${listenaddr}</td><td>${desc}</td></tr>" >> ${htmlfile}
      fi
   done
   echo "</table>" >> ${htmlfile}

   # ADD THE UNIX port checks
   echo "<p>Unix domain sockets will always be present, and" >> ${htmlfile}
   echo "it would be a hell of a job to spot possible security" >> ${htmlfile}
   echo "holes here, so this toolkit does not try.<br>" >> ${htmlfile}
   echo "Review the unix domain sockets here to see if you can" >> ${htmlfile}
   echo "identify anything that should not be running.</p>" >> ${htmlfile}
   echo "<p>This will have to always be a manual task, so the" >> ${htmlfile}
   echo "toolkit will never report alerts or violations for" >> ${htmlfile}
   echo "the unix domain sockets, check these yourself please.</p>" >> ${htmlfile}
   echo "<table border=\"1\" width=\"100%\"><tr bgcolor=\"${colour_banner}\"><td colspan=\"3\"><center>UNIX Ports open on the server</center></td></tr>" >> ${htmlfile}
   echo "<tr bgcolor=\"${colour_banner}\"><td colspan=\"3\"><center>Unix Streams Active</center></td></tr>" >> ${htmlfile}
   echo "<tr bgcolor=\"${colour_banner}\"><td>State</td><td>I-Node</td><td>Path</td></tr>" >> ${htmlfile}
   cat ${WORKDIR}/active_unix_services | grep "STREAM" | while read dataline
   do
      dataline=`echo "${dataline}" | awk -F\] {'print $2'}`
      state=`echo "${dataline}" | awk {'print $2'}`
      inode=`echo "${dataline}" | awk {'print $3'}`
      streampath=`echo "${dataline}" | awk {'print $4'}`
      echo "<tr><td>${state}</td><td>${inode}</td><td>${streampath}</td></tr>" >> ${htmlfile}
   done
   # There are not always datagram services captured, check before displaying
   # and only display if they are present.
   linecount=`cat ${WORKDIR}/active_unix_services | grep "DGRAM" | wc -l | awk {'print $1'}`
   if [ "${linecount}." != "0." ]
   then
      echo "<tr bgcolor=\"${colour_banner}\"><td colspan=\"3\"><center>Unix Datagram Connections Active</center></td></tr>" >> ${htmlfile}
      cat ${WORKDIR}/active_unix_services | grep "DGRAM" | while read dataline
      do
         dataline=`echo "${dataline}" | awk -F\] {'print $2'}`
         inode=`echo "${dataline}" | awk {'print $2'}`
         dgrampath=`echo "${dataline}" | awk {'print $3'}`
         echo "<tr><td>N/A</td><td>${inode}</td><td>${dgrampath}</td></tr>" >> ${htmlfile}
      done
   fi
   echo "</table>" >> ${htmlfile}


   # ----------------------------------------------------------
   # Added another check. When adding my overrides I found the
   # rpc tasks seemed to listen on random ports, so as fast as
   # I added a custom entry they started using another. Maybe
   # I was just missing something, but anyway...
   # To sanitise the overrides we now check the override entry
   # file and warn if there is an override for a service that
   # is no longer in use, so it can be taken out of the custom
   # file before another sly task uses it.
   # ----------------------------------------------------------
   echo "<h1>C.1.2 - TCP customisation sanitation deptartment</h1>" >> ${htmlfile}
   echo "<p>This section is just to ensure you have been keeping" >> ${htmlfile}
   echo "your customisation file clean. It will report on any allowed" >> ${htmlfile}
   echo "ports in the customisation file that were not in use at the" >> ${htmlfile}
   echo "time the snapshot was taken. This allows you to review your" >> ${htmlfile}
   echo "customisation file and adjust it if needed.</p>" >> ${htmlfile}
   delete_file "${WORKDIR}/port_sanitation"
   cat ${WORKDIR}/allowed_tcp_ports | while read dataline
   do
      portnum=`echo "${dataline}" | awk -F: {'print $2'}`
      exists=`grep -w "${portnum}" ${WORKDIR}/active_tcp_services.wrk2`
      if [ "${exists}." == "." ];
      then
         echo "<tr bgcolor=\"${colour_alert}\"><td>TCP</td><td>${portnum}</td><td>${dataline}</td></tr>" >> ${WORKDIR}/port_sanitation
         inc_counter ${hostid} alert_count
      fi
   done
   cat ${WORKDIR}/allowed_udp_ports | while read dataline
   do
      portnum=`echo "${dataline}" | awk -F: {'print $2'}`
      exists=`grep -w "${portnum}" ${WORKDIR}/active_udp_services.wrk2`
      if [ "${exists}." == "." ];
      then
         echo "<tr bgcolor=\"${colour_alert}\"><td>UDP</td><td>${portnum}</td><td>${dataline}</td></tr>" >> ${WORKDIR}/port_sanitation
         inc_counter ${hostid} alert_count
      fi
   done
   if [ -f ${WORKDIR}/port_sanitation ];
   then
      echo "<table border=\"1\"><tr bgcolor=\"${colour_banner}\">" >> ${htmlfile}
      echo "<td>Port<br>Type</td><td>Port<br>Number</td><td>Customisation file entry</td></tr>" >> ${htmlfile}
      cat ${WORKDIR}/port_sanitation >> ${htmlfile}
      echo "</table>" >> ${htmlfile}
   else
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>No problems found." >> ${htmlfile}
      echo "All customisation entries have a matching active port number." >> ${htmlfile}
      echo "No action required to the customisation files.</td></tr></table>" >> ${htmlfile}
   fi

   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"

   # Add a summary of the section to the server index, and total alert & warning counts
   server_index_addline "${hostid}" "Appendix C - Network Connectivity Checks (review)" "${htmlfile}"
} # build_appendix_c

# ----------------------------------------------------------
#                      Appendix D.
#   D. Cron security
#      D.1 - all cronjob script files secured tightly, to correct owner
# ----------------------------------------------------------
build_appendix_d() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_D.html"
   log_message ".     Building Appendix D - performing cron job security checks"

   clean_prev_work_files
   mkdir ${WORKDIR}

   echo "<html><head><title>Cron job security checks for ${hostid}</title></head><body>" >> ${htmlfile}
   echo "<h1>Appendix D - Cron Job Security Checks for ${hostid}</h1>" >> ${htmlfile}
   echo "<h2>Appendix D.1 - Insecure Cron Job Files</h2>" >> ${htmlfile}
   echo "<p>This appendix covers an often overlooked loophole. Many system admins" >> ${htmlfile}
   echo "very correctly rigidly control access to whom has access to update the" >> ${htmlfile}
   echo "cron tables; however seldom does anyone go to the bother of checking that" >> ${htmlfile}
   echo "the actual script file to be executed is secure.</p>" >> ${htmlfile}
   echo "<p>No matter how rigidly you control access to who can update the cron" >> ${htmlfile}
   echo "job table, if the actual script to be executed is writeable by others" >> ${htmlfile}
   echo "you have opened a back door.</p>" >> ${htmlfile}
   echo "<p>This section (D.1) lists all cron job files that are writeable by any user" >> ${htmlfile}
   echo "other than the owner of the crontab.<br>" >> ${htmlfile}
   echo "<b><em>Note: only checks cron jobs at this time, if you use anacron better check /etc/cron.* files manually</em></b></p>" >> ${htmlfile}
   touch ${WORKDIR}/${hostid}_all_ok

   echo "<table border=\"1\" bgcolor=\"${colour_banner}\">" >> ${htmlfile}
   echo "<tr><td><center>Cron Job Files with bad security</center></td></tr>" >> ${htmlfile}
   grep "^PERM_CRON_JOB_FILE" ${SRCDIR}/secaudit_${hostid}.txt | awk -F\= {'print $2"="$3'} | while read cronpermline
   do
      check_file_perms "${cronpermline}" "-rXXX-XX-X"
      if [ "${PERM_CHECK_RESULT}." != "OK." ]; # if not empty has error text
      then
         inc_counter ${hostid} alert_count
         echo "<tr bgcolor=\"${colour_alert}\"><td>${PERM_CHECK_RESULT}: ${cronpermline}</td></tr>" >> ${htmlfile}
      fi
   done
   echo "</b></pre>" >> ${htmlfile}

   alerts=`cat ${RESULTS_DIR}/${hostid}/alert_count`
   if [ "${alerts}." == "0." ];
   then
      echo "<tr bgcolor=\"${colour_OK}\"><td><p>There were no execptions to report for this appendix. Well done." >> ${htmlfile}
      echo "</p></td></tr></table>" >> ${htmlfile}
   else
      echo "</table><p>Secure the files above to the correct owners and file permisssions as applicable.</p>" >> ${htmlfile}
   fi

   # Report on all cron jobs
   echo "<h2>Appendix D.2 - Cron Job Report</h2>" >> ${htmlfile}
   echo "<p>These are the cron jobs identified on server <b>${hostid}</b>. Review these" >> ${htmlfile}
   echo "periodically to ensure they are still suitable for this server.</p>" >> ${htmlfile}
   echo "<table border=\"1\"><tr bgcolor=\"${colour_banner}\"><td>Crontab Type</td><td>Crontab Owner</td><td>Command Executed (without parameters)</td></tr>" >> ${htmlfile}
   grep "^PERM_CRON_JOB_FILE" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
       crondata=`echo "${dataline}" | awk -F\= {'print $3'}`
       crontype=`echo "${crondata}" | awk {'print $2'}`
       cronowner=`echo "${crondata}" | awk {'print $1'}`
       croncmd=`echo "${dataline}" | awk {'print $9'} | awk -F\= {'print $1'}`
       echo "<tr><td>${crontype}</td><td>${cronowner}</td><td>${croncmd}</td></tr>" >> ${htmlfile}
   done
   echo "</table>" >> ${htmlfile}

   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"

   # Add a summary of the section to the server index, and total alert & warning counts
  server_index_addline "${hostid}" "Appendix D - Cron Job Security Checks" "${htmlfile}"
} # build_appendix_d

# ----------------------------------------------------------
#                      Appendix E.
#   E. System file security
#      E.1 - all system files must be secured tightly
#      E.2 - check files with suid bits set
# ----------------------------------------------------------
build_appendix_e() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_E.html"
   log_message ".     Building Appendix E - system file security checks, go get a coffee"

   clean_prev_work_files
   mkdir ${WORKDIR}

   # Var is a bit of a special case as user files may be
   # stored under /var. In the customisation files you may
   # set ALLOW_SLOPPY_VAR=NO|WARN|OK to change how this is
   # reported. NO is enforce tight checking, WARN is check
   # but treat as warnings, OK is suppress, just summarise
   # what was found.
   allowsloppyvar="WARN" # default
   echo "0" > ${WORKDIR}/note_count
   override_file=""
   if [ -f ${OVERRIDES_DIR}/${hostid}.custom ];
   then
      override_file="${OVERRIDES_DIR}/${hostid}.custom"
   else
      if [ -f ${OVERRIDES_DIR}/ALL.custom ];
      then
         override_file="${OVERRIDES_DIR}/ALL.custom"
      fi
   fi
   if [ "${override_file}." != "." ];
   then
      testvar=`grep "^ALLOW_SLOPPY_VAR" ${override_file}`
      # Test and set the value here so it's only sanity
      # checked once outside the loop.
      if [ "${testvar}." != "." ];
      then
         # Provided, so check and override default of OK
         testvar=`echo "${testvar}" | awk -F\= '{print $2}'`
         if [ "${testvar}." == "WARN." ];
         then
            allowsloppyvar="WARN"
         else
            if [ "${testvar}." == "OK." -o "${testvar}." == "YES." ];
            then
               allowsloppyvar="OK"
            else
               allowsloppyvar="NO"
            fi
         fi
      fi
      # See if files under /var are permitted to be group writeable
      allowvargroupwrite="NO"
      testvar=`grep "^ALLOW_VAR_FILE_GROUPWRITE=YES" ${override_file} | awk -F\= {'print $2'}`
      if [ "${testvar}." != "YES." ];
      then
         allowvargroupwrite="NO"
      else
         allowvargroupwrite="YES"
      fi
      # save the allowed suid files now as well 
      grep "^SUID_ALLOW" ${override_file} | awk -F\= '{print $2}' | while read dataline
      do
         # note we add the space-X to force exact matches on filenames, to prevent
         # paths being used in the custom file.
         echo "${dataline} X" >> ${WORKDIR}/suid_allow_list
      done
   fi   # if overridefile exists
   cat << EOF > ${htmlfile}
<html><head><title>System file security checks for ${hostid}</title></head><body>
<h1>Appendix E - System File Security Checks for ${hostid}</h1>
<h2>E.1 System File security checks</h2>
<p>An important security consideration is that all system files are
only able to be updated by a valid system userid. This section reports
on unsafe file permissions or file ownership problems.
Basically any file updateable by other than the owner is reported here,
along with files in system directories owned by non-system users.</p>
<p>The list of users allowed to own files classed as SYSTEM are <em>${SYSTEM_FILE_OWNERS}</em>.</p>
EOF
   totalcount=0
   echo "${totalcount}" > ${WORKDIR}/system_totals_count
   grep "^PERM_SYSTEM_FILE" ${SRCDIR}/secaudit_${hostid}.txt | awk -F\= '{print $2"="$3}' | while read dataline
   do
      totalcount=$((${totalcount} + 1))
      echo "${totalcount}" > ${WORKDIR}/system_totals_count
      check_file_perms "${dataline}" "XXXXX-XX-X"
      if [ "${PERM_CHECK_RESULT}." != "OK." ]; # if not OK has error text
      then
         if [ "${allowsloppyvar}." == "NO." -a "${allowvargroupwrite}." != "YES." ];
         then
            inc_counter ${hostid} alert_count
            echo "${PERM_CHECK_RESULT}: ${dataline}" >> ${WORKDIR}/appendix_e_list
         else
            # Find out if the file is under /var
            testforvar=`echo "${dataline}" | awk -F\/ '{print $2}'`
            if [ "${testforvar}." == "var." ];
            then
               # If group write on files is OK in /var see if we
               # reset to OK with another check.
               if [ "${allowvargroupwrite}." == "YES." ];
               then
                  fileuser=`echo "${dataline}" | awk {'print $3'}`
                  filegroup=`echo "${dataline}" | awk {'print $4'}`
                  if [ "${fileuser}." == "${filegroup}." ];
                  then
                     check_file_perms "${dataline}" "XXXXXXXX-X"
                  fi
               fi
               # special checks for files under mail directory /var/spool/mail
               # if filename matched file owner and group is mail then OK
               testforspool=`echo "${dataline}" | awk -F\/ '{print $3}'`
               testformail=`echo "${dataline}" | awk -F\/ '{print $4}'`
               if [ "${testforspool}." == "spool." -a "${testformail}." == "mail." ];
               then
                  basefilename=`echo "${dataline}" | awk '{print $9}' | awk -F\= {'print $1'}`
                  basefilename=`basename ${basefilename}`
                  fileuser=`echo "${dataline}" | awk {'print $3'}`
                  filegroup=`echo "${dataline}" | awk {'print $4'}`
                  fileperms=`echo "${dataline}" | awk {'print $4'}`
                  if [ "${basefilename}." == "${fileuser}." -a "${filegroup}." == "mail." ];
                  then
                     userexists=`grep "^PASSWD_FILE=${fileuser}:" ${SRCDIR}/secaudit_${hostid}.txt`
                     if [ "${userexists}." != "." ];
                     then
                        if [ "${fileperms}." == "-rw-rw----.." ];
                        then
                           PERM_CHECK_RESULT="Bad mail file permission, expected -rw-rw---"
                        else
                           PERM_CHECK_RESULT="OK"
                        fi
                     else
                        PERM_CHECK_RESULT="Mail file owner does not exist"
                     fi
                  fi
               fi
               # and fall through to logging the error if there still is one
               if [ "${PERM_CHECK_RESULT}." != "OK." ]
               then
                  if [ "${allowsloppyvar}." == "WARN." ];
                  then
                     inc_counter ${hostid} warning_count
                     echo "${PERM_CHECK_RESULT}: ${dataline}" >> ${WORKDIR}/appendix_e_list2
                  else # else must be set as OK
                     inc_counter ${hostid} note_count
                  fi
               else # else allowed group write suppressed the alert
                  inc_counter "${hostid}" groupsuppress_count
               fi
            else # not in /var
               inc_counter ${hostid} alert_count
               echo "${PERM_CHECK_RESULT}: ${dataline}" >> ${WORKDIR}/appendix_e_list
            fi # if testforvar = var
         fi # if allowsloppyvar = NO of allowgroupwrite != YES
      fi # if permcheckresult != OK
   done
   if [ -f ${WORKDIR}/appendix_e_list ];
   then
      echo "<table border=\"1\" bgcolor=\"${colour_alert}\"><tr bgcolor=\"${colour_banner}\"><td>" >> ${htmlfile}
      echo "<center>System file security alerts</center></td></tr>" >> ${htmlfile}
      echo "<tr><td><pre>" >> ${htmlfile}
      cat ${WORKDIR}/appendix_e_list >> ${htmlfile}
      echo "</pre></td></tr></table>" >> ${htmlfile}
   else
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>No alerts for system files. No action required.</td></tr></table>" >> ${htmlfile}
   fi
   echo "</b></pre><br><br>" >> ${htmlfile}
   # report on number of files under /var that were suppressed due to the
   # custom file flag to allow group write on files.
   if [ -f ${RESULTS_DIR}/${hostid}/groupsuppress_count ];
   then
      groupsuppress=`cat ${RESULTS_DIR}/${hostid}/groupsuppress_count`
      if [ ${groupsuppress} -gt 0 ];
      then
         echo "<p>The customisation file allows files under /var to be group writeable," >> ${htmlfile}
         echo "as long as the group-id matched the user-id," >> ${htmlfile}
         echo "${groupsuppress} files were suppressed from being reported on for this reason.</p>" >> ${htmlfile}
      fi
   fi
   # Display the list of files under /var that were changes to warnings rather than
   # alerts by the allow_sloppy_var=warn flag.
   if [ -f ${WORKDIR}/appendix_e_list2 ];
   then
      echo "<p>The customisation file requested possible alerts in the /var filesystem" >> ${htmlfile}
	  echo "be downgraded to warnings. These are the problems found under /var.</p>" >> ${htmlfile}
      echo "<table border=\"1\" bgcolor=\"${colour_warn}\"><tr bgcolor=\"${colour_banner}\"><td>" >> ${htmlfile}
      echo "<center>System file security warnings</center></td></tr>" >> ${htmlfile}
      echo "<tr><td><pre>" >> ${htmlfile}
      cat ${WORKDIR}/appendix_e_list2 >> ${htmlfile}
      echo "</pre></td></tr></table>" >> ${htmlfile}
   fi
   echo "</b></pre><br><br>" >> ${htmlfile}

   # Did we suppress anything from /var ?.
   notecount=`cat ${WORKDIR}/note_count`
   if [ "${notecount}." != "0." ];
   then
      echo "<p>The customisation file for this server requested that any file security" >> ${htmlfile}
      echo "warnings under the /var filesystem be suppressed.</p>" >> ${htmlfile}
      echo "<table border=\"0\" bgcolor=\"${colour_warn}\"><tr><td>" >> ${htmlfile}
      echo "There were ${notecount} security warnings suppressed for files under /var" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
      echo "<p>If you don't know what these files are review /var, and maybe change" >> ${htmlfile}
      echo "ALLOW_SLOPPY_VAR=OK to ALLOW_SLOPPY_VAR=WARN to get a list of these files.</p>" >> ${htmlfile}
      inc_counter ${hostid} warning_count
   fi

   totalcount=`cat ${WORKDIR}/system_totals_count`
   echo "<hr><b>There were ${totalcount} file permissions checked for section E.1</b><hr>" >> ${htmlfile}

   # ---------------------------------------------------------------------------
   # now the suid file checks
   # ---------------------------------------------------------------------------
   echo "<h2>E.2 Checks for files with SUID set</h2>" >> ${htmlfile}
   echo "<p>Files with the SUID bits set can be a possible security risk." >> ${htmlfile}
   echo "All the files listed here should be checked to ensure they are still" >> ${htmlfile}
   echo "required. Any alerts raised here are for files with SUID bits set that" >> ${htmlfile}
   echo "have not been approved by the customisation file for this server," >> ${htmlfile}
   echo "a full list of all files with SUID bits set follows the alerts.</p>" >> ${htmlfile}
   # put them into a file, we want to list the whole lot at the end anyway
   grep "^SUID_FILE" ${SRCDIR}/secaudit_${hostid}.txt | awk -F\= {'print $2'} | while read dataline
   do
      echo "${dataline}" >> ${WORKDIR}/suid_file_list
   done
   if [ -f ${WORKDIR}/suid_allow_list ];
   then
      cat ${WORKDIR}/suid_file_list | while read dataline
      do
         fname=`echo "${dataline}" | awk '{print $9}'`
         # check for override
         testvar=`grep "${fname} X" ${WORKDIR}/suid_allow_list`
         if [ "${testvar}." == "." ];   # no override for this file
         then
            inc_counter ${hostid} alert_count
            echo "<tr><td>${dataline}</td></tr>" >> ${WORKDIR}/suid_alerts
         fi
      done
   else    # no overrides, all are alerts
      cat ${WORKDIR}/suid_file_list | while read dataline
      do
         inc_counter ${hostid} alert_count
         echo "<tr><td>${dataline}</td></tr>" >> ${WORKDIR}/suid_alerts
      done
   fi
   if [ -f ${WORKDIR}/suid_alerts ];
   then
      echo "<table border=\"1\" bgcolor=\"${colour_alert}\"><tr bgcolor=\"${colour_banner}\"><td>" >> ${htmlfile}
      echo "<center>Unexpected files with SUID bits set</center></td></tr>" >> ${htmlfile}
      echo "<tr><td><pre>" >> ${htmlfile}
      cat ${WORKDIR}/suid_alerts >> ${htmlfile}
      echo "</pre></td></tr></table>" >> ${htmlfile}
   else
      echo "<table bgcolor=\"${colour_OK}\"><tr><td>No unexpected SUID files found. No action required.</td></tr></table>" >> ${htmlfile}
   fi

   # and then check for stray entries in the customisation file (entries
   # in the customisation file that are no longer on the server).
   cat ${WORKDIR}/suid_allow_list | awk '{print $1}' | while read dataline
   do
      testvar=`grep "${dataline}" ${WORKDIR}/suid_file_list`
      if [ "${testvar}." == "." ];         # no longer in the file list
      then
         inc_counter ${hostid} warning_count
         echo "${dataline}" >> ${WORKDIR}/suid_missing_list
      fi
   done
   if [ -f ${WORKDIR}/suid_missing_list ];
   then
      echo "<p><b>There are problems with your customisation file for this server</b>" >> ${htmlfile}
      echo "that require your review. You have some files listed in the SUID_ALLOW" >> ${htmlfile}
      echo "section of the customisation file that either no longer exist on the server" >> ${htmlfile}
      echo "or are no longer suid files." >> ${htmlfile}
      echo "Please update the customisation file to relect the deleted files or a" >> ${htmlfile}
      echo "malicious user could create their own file in it's place and you will" >> ${htmlfile}
      echo "not get it reported here.</p>" >> ${htmlfile}
      echo "<p>The files in the customisation file that either no longer exist on the server" >> ${htmlfile}
      echo "or are no longer suid are listed below.</p>" >> ${htmlfile}
      echo "<table border=\"0\" bgcolor=\"${colour_warn}\"><tr><td><pre>" >> ${htmlfile}
      cat ${WORKDIR}/suid_missing_list >> ${htmlfile}
      echo "</pre></td></tr></table>" >> ${htmlfile}
   fi

   # and the full suid list for admins to review
   echo "<p>This is a list of all the SUID files found on the server, you should review" >> ${htmlfile}
   echo "the list periodically to ensure they are all required.</p>" >> ${htmlfile}
   echo "<table border=\"1\" bgcolor=\"${colour_warn}\"><tr bgcolor=\"${colour_banner}\"><td>" >> ${htmlfile}
   echo "<center>SUID files found on the server, are they still required ?</center></td></tr><tr><td><pre>" >> ${htmlfile}
   cat ${WORKDIR}/suid_file_list >> ${htmlfile}
   echo "</pre></td></tr></table>" >> ${htmlfile}


   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"

   # Add a summary of the section to the server index, and total alert & warning counts
   server_index_addline "${hostid}" "Appendix E - System File Security Checks" "${htmlfile}"
} # build_appendix_e

# ----------------------------------------------------------
#                      Appendix F.
#   F. Server environment
#      F.1 - motd must exist and contain reqd keywords
#      F.2 - security log retention checks
#      F.3 - ssh banner should exist and contain reqd keywords
#      F.4 - ssh must not allow direct root login
# ----------------------------------------------------------
extract_appendix_f_files() {
   hostid="$1"
   clean_prev_work_files
   mkdir ${WORKDIR}

   # /etc/motd message
   grep "^MOTD_DATA" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/motd
   done

   grep "^REQD_FILE" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/required_files
   done

   # /etc/ssh/sshd_config banner file
   grep "^SSHD_BANNER_DATA" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     # 2010/09/22 - changed cut to awk, cut wan't working ??.
     realdata=`echo "${dataline}" | awk -F\= {'print $2'}`
     echo "${realdata}" >> ${WORKDIR}/sshd_banner
   done

   # /etc/ssh/sshd_config itself
   grep "^SSHD_CONFIG_DATA" ${SRCDIR}/secaudit_${hostid}.txt | while read dataline
   do
     realdata=`echo "${dataline}" | cut -d\= -f2`
     echo "${realdata}" >> ${WORKDIR}/sshd_config
   done

} # extract_appendix_f_files

appendix_f_check_key() {
   keyid="$1"
   datafile="${WORKDIR}/key_counter"
   if [ ! -f ${datafile} ];
   then
      keycount=0
   else
      keycount=`cat ${datafile}`
   fi
   testvar=`grep -i -w "${keyid}" ${WORKDIR}/motd`
   if [ "${testvar}." != "." ];
   then
      keycount=$((${keycount} + 1))
      echo "${keycount}" > ${datafile}
   fi
} # appendix_f_check_key

build_appendix_f() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_F.html"
   log_message ".     Building Appendix F - server environment checks"

   extract_appendix_f_files "${hostid}"

   echo "<html><head><title>Server environment checks for ${hostid}</title></head><body>" >> ${htmlfile}
   echo "<h1>Appendix F - Server Environment Checks for ${hostid}</h1>" >> ${htmlfile}

   echo "<h2>F.1 - /etc/motd</h2>" >> ${htmlfile}
   errorsfound="NO"
   # 1. Check file permissions on /etc/motd
   echo "<h3>F.1.1 - File Permissions</h3>" >> ${htmlfile}
   echo "<p>A badly secured /etc/motd file can allow a malicous user" >> ${htmlfile}
   echo "to put their own, inappropriate message of the day out to" >> ${htmlfile}
   echo "all users. This should be secured so only the owner (root) can update it.</p>" >> ${htmlfile}
   testvar=`grep "^PERM_ETC_MOTD" ${SRCDIR}/secaudit_${hostid}.txt | awk -F\= {'print $2"="$3'}`
   check_file_perms "${testvar}" "-rX-r--r--"
   if [ "${PERM_CHECK_RESULT}." != "OK." ]; # if not empty has error text
   then
      inc_counter ${hostid} alert_count
      echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
      echo "<p>The file <b>/etc/motd</b> is secured so users other than <b>root</b>" >> ${htmlfile}
      echo "are able to update it.<br>" >> ${htmlfile}
      echo "${PERM_CHECK_RESULT}: ${testvar}" >> ${htmlfile}
      echo "<br><b>Correct the file permissions and ownership</b> as appropriate.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
      errorsfound="YES"
   else
	  echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
	  echo "<p>No problems. The permissions on /etc/motd are OK</p>" >> ${htmlfile}
	  echo "</td></tr></table>" >> ${htmlfile}
   fi

   # Check the contents of the motd file
   echo "<h3>F.1.2 - Contents of the file</h3>" >> ${htmlfile}
   echo "<p>The /etc/motd file should ideally be used to place the server" >> ${htmlfile}
   echo "authorised users only notice.</p>" >> ${htmlfile}
   if [ -f ${WORKDIR}/motd ];
   then
       numentries=`cat ${WORKDIR}/motd | wc -l | awk {'print $1}'`
   else
       numentries=0
   fi
   if [ "${numentries}." == "0." ];
   then
      inc_counter ${hostid} alert_count
	  echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
      echo "<p>The file <b>/etc/motd</b> is empty. Place some form of authorised" >> ${htmlfile}
      echo "user only message into it.</p>" >> ${htmlfile}
	  echo "</td></tr></table>" >> ${htmlfile}
      errorsfound="YES"
   else
      key_matches="0"
      appendix_f_check_key "unauthorised"
      appendix_f_check_key "authorised"
      appendix_f_check_key "authority"
      appendix_f_check_key "law"
      appendix_f_check_key "legal"
      appendix_f_check_key "copyright"
      key_matches=`cat ${WORKDIR}/key_counter`
      if [ "${key_matches}." == "." ];
      then
         key_matches=0
      fi
      if [ ${key_matches} -lt 1 ];
      then
         inc_counter ${hostid} alert_count
         echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
         echo "<p>The <b>/etc/motd</b> file does not contain a valid legal notice. The" >> ${htmlfile}
         echo "motd file should be used to advise anyone logging onto the server" >> ${htmlfile}
         echo "that is is for authorised users only.</p>" >> ${htmlfile}
         echo "<p>To pass this check the motd must contain at least one of the keywords here;" >> ${htmlfile}
         echo "<b>authorised, authority, copyright, law, legal</b>.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
         errorsfound="YES"
      else
         echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
		 echo "<p>The contents of the /etc/motd file are acceptable.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
      fi
   fi

   echo "<h2>F.2 - Security log retention checks</h2>" >> ${htmlfile}
   echo "<p>This section is to check on the required security log files" >> ${htmlfile}
   echo "that <b>must</b> be kept for a certain number of days to meet" >> ${htmlfile}
   echo "a general site security requirement. Generally you should" >> ${htmlfile}
   echo "keep at least 60 days of security logs.</p>" >> ${htmlfile}
   echo "<p>This appendix will always generate a warning as I have not" >> ${htmlfile}
   echo "automated processing of this information yet. Manually review" >> ${htmlfile}
   echo "the files here to ensure they are kept for the duration required.</p>" >> ${htmlfile}
   # We allow the user to turn of warnings for manual checks needed here
   if [ -f ${OVERRIDES_DIR}/${hostid}.custom ];
   then
      override_file="${OVERRIDES_DIR}/${hostid}.custom"
   else
      if [ -f ${OVERRIDES_DIR}/ALL.custom ];
      then
         override_file="${OVERRIDES_DIR}/ALL.custom"
      fi
   fi
   if [ "${override_file}." != "." ];
   then
      testvar=`grep "^NOWARN_ON_MANUALLOGCHECK.YES" ${override_file}`
      if [ "${testvar}." == "." ]
      then
         inc_counter ${hostid} warning_count  # Not automated, warning to review
         usecolour="${colour_warn}"
      else
         usecolour="${colour_OK}"
      fi
   else
      inc_counter ${hostid} warning_count  # Not automated, warning to review
      usecolour="${colour_warn}"
   fi
   echo "<table bgcolor=\"${usecolour}\" border=\"1\"><tr><td>" >> ${htmlfile}
   echo "<pre>" >> ${htmlfile}
   cat ${WORKDIR}/required_files >> ${htmlfile}
   echo "</pre>" >> ${htmlfile}
   echo "</td></tr></table>" >> ${htmlfile}

   # The SSH configuration checks
   echo "<h2>F.3 - SSHD Configuration</h2>" >> ${htmlfile}

   # Check the contents of the sshd banner file
   echo "<h3>F.3.1 - SSHD Banner file</h3>" >> ${htmlfile}
   echo "<p>SSH should be configured to display a site banner at the login prompt." >> ${htmlfile}
   echo "It should also contain an authorised users only notice.</p>" >> ${htmlfile}
   if [ -f ${WORKDIR}/motd ];
   then
       numentries=`cat ${WORKDIR}/sshd_banner | wc -l | awk {'print $1}'`
   else
       numentries=0
   fi
   if [ "${numentries}." == "0." ];
   then
      inc_counter ${hostid} alert_count
      echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
      echo "<p>The banner file configured in <b>/etc/ssh/sshd_config</b> is empty or does not exist." >> ${htmlfile}
      echo "Place some form of authorised user only message into it.</p>" >> ${htmlfile}
      echo "</td></tr></table>" >> ${htmlfile}
      errorsfound="YES"
   else
      key_matches="0"
      appendix_f_check_key "authorised"
      appendix_f_check_key "authority"
      appendix_f_check_key "law"
      appendix_f_check_key "legal"
      appendix_f_check_key "copyright"
      key_matches=`cat ${WORKDIR}/key_counter`
      if [ "${key_matches}." == "." ];
      then
         key_matches=0
      fi
      if [ ${key_matches} -lt 1 ];
      then
         inc_counter ${hostid} alert_count
         echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
         echo "<p>The banner file configured in <b>/etc/ssh/sshd_config</b> does not contain a valid legal notice. This" >> ${htmlfile}
         echo "file should be used to advise anyone logging onto the server via ssh" >> ${htmlfile}
         echo "that is is for authorised users only.</p>" >> ${htmlfile}
         echo "<p>To pass this check the motd must contain at least one of the keywords here;" >> ${htmlfile}
         echo "<b>authorised, authority, copyright, law, legal</b>.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
         errorsfound="YES"
      else
         echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
         echo "<p>The contents of the ssh banner file are acceptable.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
      fi
   fi

   echo "<h3>F.3.2 - SSHD root login setting</h3>" >> ${htmlfile}
   echo "<p>SSH should <b>not</b> permit the root account to be logged into directly." >> ${htmlfile}
   echo "That should be considered a major secirity risk." >> ${htmlfile}

   xx=`grep -i "PermitRootLogin" ${WORKDIR}/sshd_config | grep -v "^#" | grep -i "no"`
   if [ "${xx}." != "." ];
   then
         echo "<table bgcolor=\"${colour_OK}\"><tr><td>" >> ${htmlfile}
         echo "<p>The SSHD config file is setup correctly for this setting.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
   else
         inc_counter ${hostid} alert_count
         errorsfound="YES"
         echo "<table bgcolor=\"${colour_alert}\" border=\"1\"><tr><td>" >> ${htmlfile}
         echo "<p>There is no explicit 'PermitRootLogin no' statement in /etc/ssh/sshd_config." >> ${htmlfile}
         echo "It may be possible for a hacker to directly login as root. You should explicitly code this setting.</p>" >> ${htmlfile}
         echo "</td></tr></table>" >> ${htmlfile}
   fi

   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"

   # Add a summary of the section to the server index, and total alert & warning counts
   server_index_addline "${hostid}" "Appendix F - Server Environment Checks" "${htmlfile}"
} # build_appendix_f


# ----------------------------------------------------------
#                      Appendix G.
# Record the override file used (if any)
# ----------------------------------------------------------
build_appendix_g() {
   hostid="$1"
   htmlfile="${RESULTS_DIR}/${hostid}/appendix_G.html"
   log_message ".     Building Appendix G - custom file documentation"

   echo "<html><head><title>Customisation file used for ${hostid}</title></head><body>" >> ${htmlfile}
   echo "<h1>Appendix G - Customisation file used for ${hostid}</h1>" >> ${htmlfile}
   if [ "${CUSTOMFILE}." != "." ];
   then
      # A customsation file was used. Record the details
      echo "<p>A customisation file was used for this server. File used was <b>${CUSTOMFILE}</b>.</p>" >> ${htmlfile}
      echo "<p>Using a customisation file could hide some possible security vulnerabilies" >> ${htmlfile}
      echo "on the system, so you need to review the customisation file occasionally." >> ${htmlfile}
      echo "The contents of the customisation file are recorded here for you to review.</p>" >> ${htmlfile}
      echo "<table border=\"1\"><tr bgcolor=\"${colour_banner}\"><td><center>${CUSTOMFILE}</center></td></tr>" >> ${htmlfile}
      echo "<tr><td><pre>" >> ${htmlfile}
      cat ${CUSTOMFILE} >> ${htmlfile}
      echo "</pre>" >> ${htmlfile}
      echo "</td></tr></table><br><br>" >> ${htmlfile}
      # We allow the user to turn off warnings for a customisation file
      # in use, so check for this.
      testvar=`grep "^NOWARN_ON_CUSTOMFILE.YES" ${CUSTOMFILE}`
      if [ "${testvar}." == "." ]
      then
         inc_counter ${hostid} warning_count  # Not automated, warning to review
      fi
   else
      echo "<p>No customisation file was used for this server." >> ${htmlfile}
      echo "As no customisation file was used there is nothing to review.</p>" >> ${htmlfile}
   fi
   # Close the appendix page
   write_details_page_exit "${hostid}" "${htmlfile}"
   # Add a summary of the section to the server index, and total alert & warning counts
   server_index_addline "${hostid}" "Appendix G - Customisations Used" "${htmlfile}"
} # build_appendix_g

# ----------------------------------------------------------
#              build_main_index_page
# Build a master index summarising and linking to each
# servers main index and results.
# grep all servername dirs and make an index using totals
# clean the totals files also
# ----------------------------------------------------------
build_main_index_page() {
   log_message "Building main index"
   # in case a prior aborted run clear these two
   delete_file ${RESULTS_DIR}/global_alert_totals
   delete_file ${RESULTS_DIR}/global_warn_totals
   htmlfile="${RESULTS_DIR}/index.html"
   echo "<html><head><title>Server Security Report Index</title></head>" > ${htmlfile}
   echo "<body>" >> ${htmlfile}
   echo "<center><h1>Server Security Report</h1>" >> ${htmlfile}
   echo "These are the servers that have been recorded in the processing run of<br><b>" >> ${htmlfile}
   date >> ${htmlfile}
   echo "</b><br> Any alerts or warnings should be reviewed.</p>" >> ${htmlfile}
   echo "<table border=\"1\" cellpadding=\"5\">" >> ${htmlfile}
   echo "<tr bgcolor=\"${colour_banner}\"><td>Server Name</td><td>" >> ${htmlfile}
   echo "Alerts</td><td>Warnings</td><td>Snapshot Date</td><td>File<br />ScanLevel</td><td>Versions</td></tr>" >> ${htmlfile}
   # NOTE: dataline here is the directory name found, we create a index entry for each server directory
   find ${RESULTS_DIR}/* -type d | while read dataline    # /* avoids getting root directory
   do
      dataline=`basename ${dataline}`
      alerts=`cat ${RESULTS_DIR}/${dataline}/alert_totals`
      warns=`cat ${RESULTS_DIR}/${dataline}/warning_totals`
      captdate=`grep "TITLE_CAPTUREDATE" ${SRCDIR}/secaudit_${dataline}.txt | awk -F\= {'print $2'}`
      scanlevel=`grep "TITLE_FileScanLevel" ${SRCDIR}/secaudit_${dataline}.txt | awk -F\= {'print $2'}`
      extractversion=`grep "TITLE_ExtractVersion" ${SRCDIR}/secaudit_${dataline}.txt | awk -F\= {'print $2'}`
      echo "<tr><td><a href=\"${dataline}/index.html\">${dataline}</a></td><td>${alerts}</td><td>${warns}</td><td>${captdate}</td><td>${scanlevel}</td><td>Collector V${extractversion}</td></tr>" >> ${htmlfile}
      # update global titals for report summary
      update_globals "${warns}" "global_warn_totals"
      update_globals "${alerts}" "global_alert_totals"
      # do not delete the alert_totals or warning_totals files, these can be used again
      # for index rebuild when we process an individual (rather than all) server to recreate
      # the index correctly.
   done
   alerts=`cat ${RESULTS_DIR}/global_alert_totals`
   warns=`cat ${RESULTS_DIR}/global_warn_totals`
   echo "<tr bgcolor=\"${colour_banner}\"><td>TOTALS:</td><td>${alerts}</td><td>${warns}</td>" >> ${htmlfile}
   echo "<td bgcolor=\"lightblue\"><small>&copy Mark Dickinson, 2004-2020</small></td><td colspan=\"2\">Processing script V${PROCESSING_VERSION}</td></tr>" >> ${htmlfile}
   echo "</table></center><br><br>" >> ${htmlfile}
   delete_file ${RESULTS_DIR}/global_alert_totals
   delete_file ${RESULTS_DIR}/global_warn_totals
   log_message "...DONE, Built main index"
} # end of build_main_index_page

# ----------------------------------------------------------
#            perform_single_server_processing
# All the steps required to process the file associated with
# a single server.
# Moved to a seperate routine from mainline as we wish to
# allow single server processing as an option rather than
# all server processing now.
# ----------------------------------------------------------
perform_single_server_processing() {
   hostname="$1"
   FILES_PROCESSED=$((${FILES_PROCESSED} + 1))
   log_message "*********** Processing server ${hostname}, host ${FILES_PROCESSED} of ${FILES_TO_PROCESS} **********"

   # may be a new server being added so may need to create directory
   # else if a reprocess delete all prior results
   if [ ! -d ${RESULTS_DIR}/${hostname} ];
   then
      mkdir ${RESULTS_DIR}/${hostname}
   else
      /bin/rm ${RESULTS_DIR}/${hostname}/*html
      /bin/rm ${RESULTS_DIR}/${hostname}/groupsuppress_count
   fi
   clear_counter "${hostname}" alert_totals
   clear_counter "${hostname}" warning_totals
   clear_counter "${hostname}" alert_count
   clear_counter "${hostname}" warning_count
   clear_counter "${hostname}" groupsuppress_count

   locate_custom_file "${hostname}"

   update_system_file_owner_list "${hostname}"

   server_index_start ${hostname}

   build_appendix_a ${hostname}
   build_appendix_b ${hostname}
   build_appendix_c ${hostname}
   build_appendix_d ${hostname}
   build_appendix_e ${hostname}
   build_appendix_f ${hostname}
   build_appendix_g ${hostname}

   # 2010/09/22 Added the hardware profile page
   hwprof_build "${hostname}"

   server_index_end ${hostname}

   # Added to allow single server rebuilds to also rebuild any results
   # for other servers performed with a prior version of the processing
   # script.
   echo "${PROCESSING_VERSION}" > ${RESULTS_DIR}/${hostname}/report_version

   # clean temp files we do not need to retain
   delete_file "${RESULTS_DIR}/${hostname}/alert_count"
   delete_file "${RESULTS_DIR}/${hostname}/warning_count"
   delete_file "${RESULTS_DIR}/${hostname}/note_count"

   log_message "...DONE, completed processing server ${hostname}"
} # end of perform_single_server_processing

# ----------------------------------------------------------
#            perform_all_servers_processing
# Process all servers for which there exists a secaudit
# file.
# ----------------------------------------------------------
perform_all_servers_processing() {
   # remove any previous results if they exist
   if [ -d ${RESULTS_DIR} ];
   then
      rm -rf ${RESULTS_DIR}
   fi
   # And create a new results directory for this run
   mkdir ${RESULTS_DIR}
   chmod 755 ${RESULTS_DIR}

   # In case somebody visits the page frequently show an unavailable
   # message in the index.html so there is something there until the
   # main index is rebuilt at the end of the preocessing run.
   echo "<html><head></head><body><p>A full re-processing run is in progress, try again later.</p>" > ${RESULTS_DIR}/index.html
   echo "<p>Processing run started at " >> ${RESULTS_DIR}/index.html
   date >> ${RESULTS_DIR}/index.html
   echo " so try again tomorrow.</p></body></html>" >> ${RESULTS_DIR}/index.html

   # ----------------------------------------------------------
   #        Process each server file we can find
   # ----------------------------------------------------------
   ls -la ${SRCDIR}/secaudit_*.txt | while read serverfile
   do
      hostname=`echo "${serverfile}" | cut -d_ -f2`
      hostname=`echo "${hostname}" | cut -d. -f1`
      # call the common routine to process a single server for the server file found
      perform_single_server_processing "${hostname}"
   done
} # end of perform_all_servers_processing

# ----------------------------------------------------------
#              single_server_sanity_checks()
# If we are processing a single server we need to make sure
# that all other server results directories have the files
# we need present in order to rebuild the main index.
# If they do not we check if the collector source files
# exist so we can reprocess that server as well as the
# single server we were going to process origionally.
# If all checks pass this routime calls the processing for
# the servers needed to be processed.
# As the index format may change between releases we will
# also require re-processing of any server last processed
# with an older version of the processing script.
# ----------------------------------------------------------
single_server_sanity_checks() {
   hostname="$1"
   WORK1="${SINGLE_ADDITIONALS}"
   WORK2="${WORKDIR}/delme"
   delete_file "${WORK1}"
   delete_file "${WORK2}"

   if [ ! -f ${SRCDIR}/secaudit_${hostname}.txt ];
   then
      echo "***FATAL*** required input collected data file does not exist"
      echo "Missing file: ${SRCDIR}/secaudit_${hostname}.txt"
      exit 1
   fi

   find ${RESULTS_DIR}/* -type d | while read dirname    # /* avoids getting root directory
   do
      errors=0
      dirname=`basename ${dirname}`
      if [ ! -f ${RESULTS_DIR}/${dirname}/alert_totals -a "${dirname}." != "${hostname}." ];
      then
         errors=$((${errors} + 1))
      fi
      if [ ! -f ${RESULTS_DIR}/${dirname}/warning_totals -a "${dirname}." != "${hostname}." ];
      then
         errors=$((${errors} + 1))
      fi
      if [ ! -f ${RESULTS_DIR}/${dirname}/report_version -a "${dirname}." != "${hostname}." ];
      then
         errors=$((${errors} + 1))
      else
         testversion=`cat ${RESULTS_DIR}/${dirname}/report_version`
         if [ "${testversion}." != "${PROCESSING_VERSION}." ];
         then
            errors=$((${errors} + 1))
         fi
      fi
      if [ ${errors} -gt 0 ];
      then
         # can only rebuild if the source file exists
         if [ -f ${SRCDIR}/secaudit_${dirname}.txt ];
         then
            echo "Processing must also be performed on server ${dirname} to ensure consistency"
            echo "${dirname}" >> ${WORK1}
         else 
            echo "***FATAL ERROR*** server ${dirname} is missing required result"
            echo ".                 files and there is no collector file to"
            echo ".                 rebuild the files from"
            echo "Y" > ${WORK2}
         fi
      fi
   done
   if [ -f ${WORK2} ];
   then
      echo "Errors prevent processing from being performed."
      delete_file "${WORK1}"
      delete_file "${WORK2}"
      exit 1
   fi
   # Are there additional servers we must also process ?.
   if [ -f ${WORK1} ];
   then
      echo "***** In order to process server ${hostname} we must also process"
      echo ".     the servers listed below as they are missing required files"
      echo ".     needed to build the main index page."
      cat ${WORK1}
      read -p "Do you wish to continue (y/n)?" testvar
      if [ "${testvar}." != "y." -a "${testvar}." != "Y." ];
      then
         echo "Aborting processing at user request."
         exit 1
      fi
   fi
   # else all is OK,
   # additional server list (if any) stored in file referenced
   # by SINGLE_ADDITIONALS.
   # Add the hsotname we origionally needed to process to that
   # list also.
   echo "${hostname}" >> ${WORK1}
   FILES_TO_PROCESS=`cat ${WORK1} | wc -l`
   cat ${WORK1} | while read thehost
   do 
      perform_single_server_processing "${thehost}"
   done
   delete_file "${WORK1}"
   delete_file "${WORK2}"
} # end of single_server_sanity_checks

# ==========================================================
#                       MAINLINE
# ==========================================================
marks_banner

# We need the results directory
if [ ! -d ${RESULTS_DIR} ];
then
   mkdir ${RESULTS_DIR}
   chmod 755 ${RESULTS_DIR}
fi

# And we need an empty work directory
clean_prev_work_files
mkdir ${WORKDIR}
chmod 755 ${WORKDIR}

# ----------------------------------------------------------
#      Default is still to process all files found
# in-progress - if a single server jump to it via the
# 'single_server_sanity_checks "${hostname}" interface
# ----------------------------------------------------------
if [ "${SINGLESERVER}." == "." ];
then
   perform_all_servers_processing
else
   single_server_sanity_checks "${SINGLESERVER}"
fi

# ----------------------------------------------------------
# Create the main top-level consolidated index page now
# ----------------------------------------------------------
build_main_index_page

# ----------------------------------------------------------
# Optional additional processing
# ----------------------------------------------------------
# Create a compressed results file in case these reports
# are to be archived for historical purposes.
if [ "${ARCHIVEDIR}." != "." ];
then
   log_message "Creating a backup archive of the reports"
   rundatestamp=`date +"%Y%m%d"`
   delete_file ${ARCHIVEDIR}/reports_${rundatestamp}.tar.gz
   savedir=`pwd`
   cd ${RESULTS_DIR}
   tar -zcf ${ARCHIVEDIR}/reports_${rundatestamp}.tar.gz *
   cd ${savedir}
   log_message "...DONE, archive created as ${ARCHIVEDIR}/reports_${rundatestamp}.tar.gz"
fi

# we need to clean up the work directory
clean_prev_work_files

log_message "Processing has completed, review the results in the web pages created please."
exit 0