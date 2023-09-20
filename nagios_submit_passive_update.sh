#!/bin/bash
# =============================================================================
#
# nagios_submit_passive_update.sh  (V0.02)
#
# For Debian user this REQUIRED package netcat-openbsd, it will not work
# with the package netcat-traditional (both behave differently to the version
# of netcat with alma/rocky/fedora, a pain to figure out).
#
# There are three "CHANGE ME" lines in the glocal vales to change section
# you will need to update to use this.
#
# Nagios allows scripts to write process check information directly to the
# pipe which it uses as an external command file. While useful it requires
# the scripts to run on the server running nagios where they have access to 
# that pipe... but how to get remote servers to post passive updates then.
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
# environment). Maybe oneday adjust so it always stays listening but that
# is less portable between distros (Deb12 nc has different parms to Rhel nc for example).
# But a script is simple for anyone to maintain and customise and is
# a workable solution.
# - basic sanity checking is done on input prior to a message being posted
# - basic sanity checking is done of the listening side to ensure the
#   message recieved is valid, as there is no guarantee of the message
#   source. Could change nc to listen on a specific internal interface
#   but I don't need that yet.
#
# Syntax: refer to the examples below
# Note:   The service name must exactly match (case sensitive) the service
#         name defined to nagios.
#
# Requires...
#  - The nc command 
#        provided by the nmap-ncat package in Fedora/Alma/Rocky
#        provided by netcat-openbsd package on Debian
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
#    The script must be in a directory the nagios user can read (as you should
#    run the server function as the nagios user).
#    
# I have used this on    
# V0.01 This script has been tested/used on Fedora 29 and nagios core 4.3.4 
# V0.02 This script has been tested/used on Debian12 and nagios core 4.4.6,
#       and this version I run from a systemd service entry now
#    
# --- Nagios service example ---
# Notes: if "active_checks_enabled 0" is used there is s warning on the
#        dashboard saying the service active check is disabled, so I leave
#        it enabled with a huge recheck time. The retry_interval check
#        is triggered as soon as a not OK is posted and we do not want it
#        to do anything so another huge time period before it runs (an OK
#        passive post should be there within 7 days you would hope); the
#        max_check_attampts cannot be 0, the check_command cannot be empty
#        so have something that that returns OK when nagios forst starts up
#        and to produce an OK when it runs every 7 days.
#        The "service_description" is what you post updates to with this script.
#define service{
#        use                             local-service       
#        hostgroup_name                  all-hosts      ; your hostgroup here
#        service_description             Passive-slot1  ; << name of passive update target service
#        check_command                   check_nrpe!md_passive_default
#        check_interval                  10080    ; active checks only once every 7 days
#        retry_interval                  10080    ; for a non-OK do not retry for 7 days
#        passive_checks_enabled          1        ; passive checks any time
##       active_checks_enabled           0        ; disable active checks, places warning on dashboard
#        max_check_attempts              1        ; for non-OK retry N times at retry_interval
#                                                 ; max_check_attempts cannot be 0
#        }
#    
# --- Important notes on examples here ---
# I would put the script file in /usr/local/bin, as it is probably not
# going to be the nagios user generating passive updates so it needs to
# be somewhere all users can run it... just ensure only the nagios user
# ever runs the server function.
#    
# --- Script post examples, using above service_description ---
# ./nagios_submit_passive_update.sh postcrit Passive-slot1 "Test Passive Crit Alert"
# ./nagios_submit_passive_update.sh postwarn Passive-slot1 "Test Passive Warn Alert"
# ./nagios_submit_passive_update.sh postok Passive-slot1 "All OK again"
#    
# --- Script run as message reciever on the nagios[4] host ---
# assumes: the script is is a folder nagios has access to, such as /home/nagios here
# su - nagios -s /bin/bash -c "nohup /usr/local/bin/nagios_submit_passive_update.sh server &"
#
# --- Example systemd service entry ---
#   # /usr/lib/systemd/system/marks_nagios_passivegw.service
#   [Unit]
#   Description=Nagios passive update gateway
#   #Documentation=man:manpagetodo(1)
#   After=network.target network-online.target
#   [Service]
#   Type=simple
#   WorkingDirectory=/var/tmp
#   ExecStart=/usr/local/bin/nagios_submit_passive_update.sh server
#   ExecStop=/usr/local/bin/nagios_submit_passive_update.sh stop
#   RuntimeDirectory=y
#   RuntimeDirectoryMode=0755
#   TimeoutStopSec=10
#   User=nagios
#   Group=nagios
#   PrivateTmp=true
#   KillMode=control-group
#   [Install]
#   WantedBy=multi-user.target
# --- End of Example systemd service entry ---
#    
# =============================================================================

# -----------------------------------------------------------------------------
# Global variables you may (probably WILL) need to change.
# -----------------------------------------------------------------------------

# The hostname of your nagios server. Must be resolveable by name
# by any server using the post function.
NAGIOS_HOSTNAME="nagios2"                    # CHANGE ME : hostname running nagios[4]

# The port this script will listen on when running as a server.
# On your nagios host (with the port number you use)
#     firewall-cmd --add-port 9010/tcp     (and test it, then...)
#     firewall-cmd --add-port 9010/tcp --permanent
NAGIOS_SCRIPT_LISTENPORT="9010"              # CHANGE ME : port this script listens/posts to

# The nagios command file configured for use ny nagios
# Defined in nagios config with the command_file entry
#                                                  # CHANGE ME : check below fpr your distribution
#NAGIOS_CMDFILE="/var/spool/nagios/cmd/nagios.cmd" # default nagios command pipe file RHEL
NAGIOS_CMDFILE="/var/lib/nagios4/rw/nagios.cmd"    # default nagios command pipe file Debian

# -----------------------------------------------------------------------------
# End of Glocal variables you will need to change
# -----------------------------------------------------------------------------

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
        ... hostname is the name of the host the service check is for, not the nagios server hostname,
            this long methos allows overriding the hostname the check is for
        ... service-description must exactly match the nagios service description (case sensitive)
     OR : ${scriptname} postok service-description plugin-output   (uses current hostname, fills in RC)
	  ${scriptname} postwarn service-description plugin-output (uses current hostname, fills in RC)
	  ${scriptname} postcrit service-description plugin-output (uses current hostname, fills in RC)

To run as a server  : nohup ${scriptname} server
... su - nagios -s /bin/bash -c "cd /home/nagios;nohup ./nagios_submit_passive_update.sh server &"

other   : ${scriptname} status | ${scriptname} stop 
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
      remote_text=`nc -l -p ${NAGIOS_SCRIPT_LISTENPORT}`
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
#    postok|postwarn|postcrit - post but the script fills in hostname and rtncode
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
              isdebian=`uname -a | grep -i debian`
              if [ "${isdebian}." != "." ];
              then
                 ncopts="-N"  # if not present end of data does not close/end connection
                              # requires package netcat-openbsd, not netcat-traditional
              else
                 ncopts="-4"  # use ipv4 only, this flag not supported ne debian netcat-bsd
              fi
              echo "${cmdline}" | nc ${ncopts} ${NAGIOS_HOSTNAME} ${NAGIOS_SCRIPT_LISTENPORT}
              nc_result="$?"
              if [ "${nc_result}." != "0." ];
              then
                 echo "Failed to post message to ${NAGIOS_HOSTNAME} on port ${NAGIOS_SCRIPT_LISTENPORT}"
                 echo "nc (netcat) response code was ${nc_result}"
                 echo "Check the remote listener is running and firewall port is enabled"
                 exit 1
              fi
              ;;
   "postok")  desc="$1"
              plugin_output="$2"
	      hostname=`hostname | awk -F. {'print $1'}`
              return_code="0"
	      $0 post "${hostname}" "${desc}" "${return_code}" "${plugin_output}"
              ;;
   "postwarn") desc="$1"
              plugin_output="$2"
	      hostname=`hostname | awk -F. {'print $1'}`
              return_code="1"
	      $0 post "${hostname}" "${desc}" "${return_code}" "${plugin_output}"
              ;;
   "postcrit") desc="$1"
              plugin_output="$2"
	      hostname=`hostname | awk -F. {'print $1'}`
              return_code="2"
	      $0 post "${hostname}" "${desc}" "${return_code}" "${plugin_output}"
              ;;
   "server")  myhostname=`hostname | awk -F. {'print $1'}` # don't care about domaun name
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
              psline=`ps -ef | grep "nc -l -p ${NAGIOS_SCRIPT_LISTENPORT}" | grep -v grep | grep "${myuserid}"`
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
              pid2=`ps -ef | grep "nc -l -p ${NAGIOS_SCRIPT_LISTENPORT}" | grep -v grep | grep "${myuserid}" | awk {'print $2'}`
              if [ "${pid2}." != "." ];
              then
                 kill -9 ${pid2}
                 pid2=`ps -ef | grep "nc -l -p ${NAGIOS_SCRIPT_LISTENPORT}" | grep -v grep | grep "${myuserid}" | awk {'print $2'}`
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
