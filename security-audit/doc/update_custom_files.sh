#!/bin/bash
#
# This is in the doc directory as it is a temporary file that
# is refered to in the changes.txt file as a migration aid script.
# It will be removed after a few versions.
#
# Between version 0.24 and 0.25 fields that did not need to have
# values terminated with : should now have that termination value.
# This script will try to update all the custom files in a directory.
# It will backup the files before changing them, UNLESS there are
# already backup files of them in the dir (as I might be running
# this lots of times to check it works and do not want to overwrite
# backups if it doesn't)..
#
# Syntax: script dir-with-custom-files backup-dir
#
# backup-dir directory must exist
#
# examples:
#   doc/update_custom_files.sh custom_includes backups
#   doc/update_custom_files.sh custom backups
#
# Field values that must terminate with : now
#   ALLOW_OWNER_ROOT
#   ALLOW_DIRPERM_SYSTEM
#   SUID_ALLOW
#   SUDOERS_ALLOW_ALL_SERVERS
#   SUDOERS_ALLOW_ALL_COMMANDS
#   ALLOW_DIRPERM_EXPLICIT
#   FORCE_ANYFILE_OK
#   NETWORK_....._PROCESS_ALLOW
#
dirtoprocess="$1"
backupdir="$2"

runuser=`whoami`
if [ "${runuser}." == "root." ];
then
   echo "DO NOT RUN THIS SCRIPT AS THE ROOT USER !"
   exit 1
fi

# If relative paths were provided we want to get the full path.
mydir=`pwd`
if [ "${dirtoprocess}." == "." ];
then
   echo "A directory containing custom files must be provided."
   echo "Syntax: $0 dirpath backupdir"
   exit 1
else
   if [ -d ${dirtoprocess} ];
   then
      cd "${dirtoprocess}"
      dirtoprocess=`pwd`
      cd "${mydir}"
   else
      echo "Directory ${dirtoprocess} does not exist."
      echo "Syntax: $0 dirpath backupdir"
      exit 1
   fi
fi
if [ "${backupdir}." == "." ];
then
   echo "A backup directory must be provided."
   exit 1
else
   if [ -d ${backupdir} ];
   then
      cd "${backupdir}"
      backupdir=`pwd`
      cd "${mydir}"
   else
      echo "Directory ${backupdir} does not exist."
      echo "Syntax: $0 dirpath backupdir"
      exit 1
   fi
fi

# return
#   0 if no modification needed
#   1 modification may be needed, one data field value
#   2 modification may be needed, two data field values
#   9 modification may be needed, random number of fields possible
#   Number of fields is important, we do not want to add any required
#   : byte after comments if any are on the line
match_test() {
   yy="$1"
   returnvar=0
   xx=`echo "${yy}" | grep "^ALLOW_OWNER_ROOT"`
   if [ "${xx}." != "." ];
   then
      returnvar=1
   fi
   xx=`echo "${yy}" | grep "^ALLOW_DIRPERM_SYSTEM"`
   if [ "${xx}." != "." ];
   then
      returnvar=1
   fi
   xx=`echo "${yy}" | grep "^SUID_ALLOW"`
   if [ "${xx}." != "." ];
   then
      returnvar=1
   fi
   xx=`echo "${yy}" | grep "^SUDOERS_ALLOW"`
   if [ "${xx}." != "." ];
   then
      returnvar=1
   fi
   xx=`echo "${yy}" | grep "^ALLOW_DIRPERM_EXPLICIT"`
   if [ "${xx}." != "." ];
   then
      returnvar=2
   fi
   xx=`echo "${yy}" | grep "^FORCE_ANYFILE_OK"`
   if [ "${xx}." != "." ];
   then
      returnvar=2
   fi
   # this could have many fields, I had one with 8
   xx=`echo "${yy}" | grep "^NETWORK_....._PROCESS_ALLOW"`
   if [ "${xx}." != "." ];
   then
      returnvar=9
   fi
   echo ${returnvar}
} # end match_test

# If the line already has a trailing : we do not want to add another
write_sane_value() {
   fname="$1"
   datavalue="$2"
   xx=${datavalue:$(( ${#datavalue} - 1)):1}
   if [ "${xx}." == ":." ];
   then    # it already has a trailing :, write as is
      echo "${datavalue}" >> ${fname}
   else    # else it needs  trailing : added
      echo "${datavalue}:" >> ${fname}
   fi
} # end write_sane_value

# --- rework all files in a directory ---
all_in_dir() {
   dirselect="$1"
   if [ -d ${dirselect} ];
   then    
      cd ${dirselect}
      ls | while read fname
      do
         if [ ! -f "${backupdir}/${fname}" ];
         then
            /bin/mv "${fname}" "${backupdir}/${fname}"  # MOVE TO BACKUP if not already there
         else
            /bin/rm "${fname}"  # don't want to apend, we are replacing it from the backup
         fi
         cat "${backupdir}/${fname}" | while read dataline
         do
            parsecheck=`match_test "${dataline}"`
	    case "${parsecheck}" in
            "1")
               varpart=`echo "${dataline}" | awk {'print $1'}`
               write_sane_value "${fname}" "${varpart}" 
               ;;
            "2")
               varpart=`echo "${dataline}" | awk {'print $1" "$2'}`
               write_sane_value "${fname}" "${varpart}" 
               ;;
            "9")
               # if there were comments/junk at end of line this won't work but we assume none of those present
               varpart=`echo "${dataline}" | awk -F\# {'print $1'}`   # best guess delim if there were comments
               write_sane_value "${fname}" "${varpart}" 
               ;;
            *)  # else line is not a value we are changing
               echo "${dataline}" >> ${fname}
               ;;
            esac
         done
      done
   fi
} # end all_in_dir

# so change all the origional files now
all_in_dir "${dirtoprocess}"
exit 0
