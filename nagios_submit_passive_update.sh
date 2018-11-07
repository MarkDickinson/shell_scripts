#!/bin/bash
# =============================================================================
#
# nagios_submit_passive_update.sh
#
# Nagios allows scripts to write process check information directly to the
# pipe which it uses as an external command file. While useful it requires
# the scripts to run on the server running nagios where they have access to 
# that pipe.
# The solution is to have a server process running on the nagios server that
# accepts passive alerts sent from remote servers, and this process writes to
# the nagios external command pipe on their behalf. There are some utilities
# on the exchange.nagios.org site such as the NCSA plugin but they do not
# seem to be actively maintained.
#
# This is my simple solution, a bash script that can run either as the
# server process or as the client posting a passive status update to
# nagios via this server process. IT IS NOT SUITABLE FOR AN ENVIRONMENT
# WITH A HIGH VOLUME OF PASSIVE STATUS UPDATES as the "nc" listening 
# process stops when a message is recieved and needs to do a lot of 
# awking and sanity checking of the message recieved before it loops around
# to restart the nc process (so you will lose messages in a high volume
# environment).
# But a script is simple for anyone to maintain and customise and is
# a workable solution.
# - basic sanity checking is done on input prior to a message being posted
# - basic sanity checking is done of the listening side to ensure the
#   message recieved is valid, as there is no guarantee of the message
#   source
#
# Syntax: refer to the show_syntax subroutine
#
# Requires...
#  - The nc command (provided by the nmap-ncat package in Fedora)
#  - A server with nagios running on it, configured to accept passive commands
#  - one or more services defined in that nagios configuration that can
#    accept passive updates
#  - The port you select is setup in your firewall rules on the server running
#    the nagios application
#  - The user running the script (as a server) must have write access to the
#    nagios external command pipe file (as always do not run as root)
#  - recomended it be run with nohup and backgrounded if you are running it
#    as a server, unless you have a terminal or "screen" session you can
#    tie up :-)
#    ie:su - nagios -c "cd /home/nagios;nohup ./nagios_submit_passive_update.sh server &
#    
# This script has been tested/used on Fedora 29 and nagios core 4.3.4 (the
# version shipped with Fedora).
#    
# =============================================================================

# -----------------------------------------------------------------------------
# Global variables you may (probably will) need to change.
# -----------------------------------------------------------------------------
NAGIOS_HOSTNAME="nagios"                          # servername nagios runs on
NAGIOS_SCRIPT_LISTENPORT="9010"                   # port this script listens/posts to
NAGIOS_CMDFILE="/var/spool/nagios/cmd/nagios.cmd" # name of nagios command pipe file

# -----------------------------------------------------------------------------
# Show the basic usage syntax. This is invoked if input fails the basic
# sanity checks used with a post command of script options.
# -----------------------------------------------------------------------------
show_syntax() {
   scriptname=`basename$0`
   cat << EOF
${scriptname} : script to submit passive checks to a nagios server

This script can either run a a listening server (on the nagios host) to accept
passive check messages to be posted to the nagios command file; or it can be
used to post messages to the listening script.

To post : ${scriptname} post hostname service-description return-code plugin-output
Server  : nohup ${scriptname} server
other   : ${scriptname} status | ${scriptname} stop  (To manage the server invokation)
EOF
} # end show_syntax

# -----------------------------------------------------------------------------
# Used in the server_task routine.
# Log the reason why a message recieved was discarded and the message itself.
# A seperate routine rather than using logger in the mainline as you may wish
# to change this to write to a logfile.
# -----------------------------------------------------------------------------
my_logger() {
   scriptname=`basename $0`
   logger "${scriptname}:$*"
} # end my_logger

# -----------------------------------------------------------------------------
# Loop forever (or until another copy of the script is run by the same user
# with the "stop" option) to
# - start a nc task listening on the port
# - read the passive command text recieved
# - basic sanity checks for valid message text, plus also discard the message
#   if the message timestamp is <> 2mins from the current nagios server time
# - if the message seems ok write it to the nagios external command pipe
# - loop back to starting a new nc task listening on the port for the next message
# -----------------------------------------------------------------------------
server_task() {
   while [ 1 ];
   do
      remote_text=`nc -4 -l ${NAGIOS_HOSTNAME} ${NAGIOS_SCRIPT_LISTENPORT}`
      datetimenow=`date +%s`
      datetimemax=$((${datetimenow} + 120))
      datetimemin=$((${datetimenow} - 120))
      timestamp=`echo "${remote_text}" | awk {'print $1'} | sed -e's/\[//' | sed -e's/\]//'`
      wrk1=`echo "${remote_text}" | awk {'print $2'} | awk -F\; {'print $1'}`
      wrk2=`echo "${remote_text}" | awk -F\; {'print $2";"$3";"$4";"$5'}`
      textbuffer="${wrk1};${wrk2}"
      cmdused=`echo "${textbuffer}" | awk -F\; {'print $1'}`
      rmthost=`echo "${textbuffer}" | awk -F\; {'print $2'}`
      servicename=`echo "${textbuffer}" | awk -F\; {'print $3'}`
      respcode=`echo "${textbuffer}" | awk -F\; {'print $4'}`
      resptext=`echo "${textbuffer}" | awk -F\; {'print $5'}`
      discard="NO"
      if [ "${cmdused}." != "PROCESS_SERVICE_CHECK_RESULT." ];
      then
         discard="YES"
         my_logger "Invalid command text recieved"
      elif [ ${timestamp} -gt ${datetimemax} -o ${timestamp} -lt ${datetimemin} ];
      then
         discard="YES"
         my_logger "Message timestamp <> 2min allowance"
      elif ! [[ $respcode =~ ^[0-9]+$ ]];
      then
         discard="YES"
         my_logger "Message contains illegal response code"
      elif [ $respcode -gt 3 ];
      then
         discard="YES"
         my_logger "Message contains illegal response code"
      fi
      if [ "${discard}." != "NO." ];
      then
         my_logger "discarded ${remote_text}"
      else
         my_logger "accepted:${remote_text}"
         echo "${remote_text}" >> ${NAGIOS_CMDFILE}
      fi
   done
} # end server_task

# -----------------------------------------------------------------------------
# Perform the required operation
#    post: sanity check the input and post the message to the listening process
#    server: run as a looping listening process to read posted messages, sanity
#            check them and write them to the nagios external command file
#    status: show if we have a looping nc process for this script
#    stop: stop any running looping nc script for this user/server/port
#          combination
# -----------------------------------------------------------------------------
command="$1"
shift
case "${command}" in
   "post")    host_name="$1"
              desc="$2"
              return_code="$3"
              plugin_output="$4"
              if [ "${plugin_output}." == "." ];
              then
                 show_syntax
                 exit 1
              fi
              # Check that the return code is numeric and the value 0 to 3
              if ! [[ $return_code =~ ^[0-9]+$ ]];
              then
                 echo "Response code value is not numeric."
                 echo "Response code value must be a number from 0 to 3."
                 exit 1
              fi
              if [ ${return_code} -gt 3 ];
              then
                 echo "Response code value is too high."
                 echo "Response code value must be a number from 0 to 3"
                 exit 1
              fi
              # get the current date/time in seconds since UNIX epoch
              datetime=`date +%s`
              # create the command line to add to the command file
              cmdline="[${datetime}] PROCESS_SERVICE_CHECK_RESULT;${host_name};${desc};${return_code};${plugin_output}"
              echo "${cmdline}" | nc -4 ${NAGIOS_HOSTNAME} ${NAGIOS_SCRIPT_LISTENPORT}
              nc_result="$?"
              if [ "${nc_result}." != "0." ];
              then
                 echo "Failed to post message to ${NAGIOS_HOSTNAME} on port ${NAGIOS_SCRIPT_LISTENPORT}"
                 echo "nc (netcat) response code was ${nc_result}"
                 echo "Check the remote listener is running and firewall port is enabled"
                 exit 1
              fi
              ;;
   "server")  myhostname=`hostname`
              if [ "${myhostname}." != "${NAGIOS_HOSTNAME}." ];
              then
                 echo "Server mode is only expected to be used on the server running nagios !"
                 exit 1
              fi
              if [ ! -p ${NAGIOS_CMDFILE} ];
              then
                 echo "No pipe named ${NAGIOS_CMDFILE}"
                 echo "Either this is not a nagios server or nagios is not running"
                 echo "Nagios must be running before this script is started as a server !"
                 exit 1
              fi
              if [ ! -w ${NAGIOS_CMDFILE} ];
              then
                 myuserid=`whoami`
                 echo "$0 is running as user ${myuserid}"
                 echo "User ${myuserid} does not have write authority to ${NAGIOS_CMDFILE}"
                 exit 1
              fi
              myuserid=`whoami`
              if [ "${myuserid}." == "root." ];
              then
                 my_logger "WARNING:SHOULD NOT BE RUN AS ROOT, continuing anyway"
              fi
              my_logger "running as user ${myuserid}"
              server_task
              ;;
   "status")  myuserid=`whoami`
              myname=`basename $0`
              psline=`ps -ef | grep "nc -4 -l ${NAGIOS_HOSTNAME} ${NAGIOS_SCRIPT_LISTENPORT}" | grep -v grep | grep "${myuserid}"`
              if [ "${psline}." != "." ];
              then
                 echo "nc process is running"
                 echo "${psline}"
                 psline=`ps -ef | grep "${myname}" | grep -v grep | grep "${myuserid}" | grep -v "${myname} status"`
                 echo "${psline}"
              else
                 echo "nc process is not running"
              fi
              ;;
   "stop")    myuserid=`whoami`
              myname=`basename $0`
              # kill the wrapper (this script) first to stop it restarting
              # the nc process.
              pid1=`ps -ef | grep "${myname}" | grep -v grep | grep "${myuserid}" | grep -v "${myname} stop" | awk {'print $2'}`
              if [ "${pid1}." != "." ];
              then
                 kill -9 ${pid1}
              fi
              # Then stop the nc process if we can find one
              pid2=`ps -ef | grep "nc -4 -l ${NAGIOS_HOSTNAME} ${NAGIOS_SCRIPT_LISTENPORT}" | grep -v grep | grep "${myuserid}" | awk {'print $2'}`
              if [ "${pid2}." != "." ];
              then
                 kill -9 ${pid2}
                 pid2=`ps -ef | grep "nc -4 -l ${NAGIOS_HOSTNAME} ${NAGIOS_SCRIPT_LISTENPORT}" | grep -v grep | grep "${myuserid}" | awk {'print $2'}`
                 if [ "${pid2}." == "." ];
                 then
                    echo "Process has been stopped"
                 else
                    echo "Unable to stop the nc process ${pid2}"
                 fi
              else
                 echo "No nc program running for this script under userid ${myuserid}"
              fi
              ;;
   *)         show_syntax
              exit 1
              ;;
esac
exit 0 
