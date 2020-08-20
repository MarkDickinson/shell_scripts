# --------------------------------------------------------------------------------------------------------------
#
# BETA: not implemented in mainline code yet
#       To be implemented in collection script for 0.13 or 0.14 or when I am happy with it
#
# Intent: To replace the existing command locate parsing that currently only checks the
#         first command of a multiline crontab command.
#
# Try to identify all commands being run in multi-command crontab lines so all can be checked,
# also for commands such as php/bash/sh locate the file being run by those as the target to be
# checked rather than the system/interpreter commands themselves,
# also identify commands that make checks impossible, such as a 'cd' in the command which
# changes the environment, plus commands such as ./xxx that cannot be checked as we do not 
# know every users starting environment (and I don't intend to code for parsing users
# .profile/.bashrc/etc at this rime to handle that), plus commands that do not need to
# be checked such as 'ls' (as when piping is handled we would check what gets the
# piped output)
#
# Current issues preventing implementation
#  (1) I have only just started on this, its not ready yet :-)
#  (2) does not yet handle the pipe ( | ) as a command seperator, which is needed
#  (3) need to rethink passing '*' as a data parameter, it can be in the crontab line,
#      tr '*' to 'X' before using this code anywhere
#  (4) clean up the code, remove resundant and debug bits inserted for testing
#
# --------------------------------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------------------------------
# Lists of commands for special handling
# --------------------------------------------------------------------------------------------------------------
CRON_CMD_IGNORE_LIST="/usr/bin/echo /bin/echo /usr/bin/ls"                      # commands to ignore
CRON_CMD_SHELL_LIST="/usr/bin/php /usr/bin/bash /usr/bin/csh /usr/bin/sh sh"    # commands we want the second field as...
                                                                                #    ...the command being executed
CRON_CMD_FATAL_LIST="/usr/bin/cd /usr/bin/find"                                 # commands that will invalidate all checks

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
   var1=`echo "$*" | cut -d " " -f 6-999`
   # and the rest of the data is the commands to check
   echo "Debug - parsing data line:${var1}"
   while [ ${#var1} -gt 0 ];
   do 
      wasandand="no"
      var2=`echo "${var1}" | awk -F\; {'print $1'}`
      var3=`echo "${var1}" | awk -F\& {'print $1'}`
      len2=${#var2}
      len3=${#var3}
      if [ ${len2} -lt ${len3} ];
      then
         uselen=${len2}
      else
         uselen=${len3}
         wasandand="yes"
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
         cmdexists=`which ${firstpart} 2>/dev/null`
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
               cmdexists=`which ${firstpart} 2>/dev/null`
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
               echo "NOTFOUND:${firstpart}:does not exist or is not in searchlist"
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
# Testing with known parameters
# --------------------------------------------------------------------------------------------------------------
cron_parse_out_commands '23 10 * * 6 /usr/bin/php command-file opts;/bin/echo "some test" && /bin/echo "new text"'
cron_parse_out_commands "23 10 * * 6 cd /some/dir;ls -la"
cron_parse_out_commands '23 10 * * 6 sh -c "/run/some/script1;/run/another/script2"'
# still to parse for pipe
# cron_parse_out_commands "40 18 * * 0 echo "Some text to sound" | espeak --stdin"

# stess it a bit, use real data; less the comments and blank lines
crontab -l | grep -v "^#" | while read dataline
do
   if [ "${dataline}." != "." ];   # ignore blank lines
   then
      cron_parse_out_commands "${dataline}"
   fi
done

exit 0
