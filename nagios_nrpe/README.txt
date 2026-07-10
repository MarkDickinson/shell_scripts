I have dozens of site specific NRPE check scripts which are pointless here.

But I also have a few 'generic' ones for things not yet available
out-of-the-box that may be useful to anyone interested.

Note: I run them all using NRPE.
Note2: They are all BASH scripts, bash is required not sh/ksh etc.

Quick index:
   - posting passive checks from remote servers
   - checking last patching date (handles: rhel/dnf, debian/apt, openindiana/pkg)
   - determining if ntpd or chronyd is in use and checking
     time sync with the correct commands (ntpq or chronyc)

----------------------------------------------------------
--- using passive services to post custom updates      ---
----------------------------------------------------------
History:
   Nagios allows service check status to be updated by manually writing
   updates to its command pipe; which is only really useful on the server
   running nagios itself.
   I wanted remote servers to be able to post updates, so wrote a script
   to make that possible. I have a few 'passive' services defined for
   some monitored hosts that those remote hosts can post crit|warn|ok updates to.

Scripts are
   md_passive_default   (does nothing but return OK)
       - the service needs a script to run on periodic checks, this just returns OK
         You would have a 'passive' service defined in nagios that only runs one a day
         or week by itself, that you intend to manually (or from otehr scripts) provide
         status updates to. The service needs a check script defined as when nagios
         starts it will want to in a staggered fashion run the check scripts for all
         services defined, so it needs one that returns a valid result
   nagios_submit_passive_update.sh  [ !!! edit entries tagged with CHANGE ME !!! ]
       - (a) script runs on nagios server to accept posts from remote servers
             and write to nagios command pipe
             note: how to run this as a systemd service is in the script comments
         (b) script can be run on remote servers to post messages to (a)
   nagios/nrpe simple config
       in a file under directory nrpe.d you would have additional commands defined
       !!! this example is for Debian (rhel uses lib64 not lib, openindiana probably /usr/local/nagios/libexec)
          command[md_passive_default]=/usr/lib/nagios/plugins/md_passive_default
          command[md_check_passive_service]=/usr/lib/nagios/plugins/md_check_passive_service
       in your nagios main config you would have something like the below
define service{
        use                             local-service         ; Name of service template to use
        hostgroup_name                  all-linux-hosts       ; groups of servers
        host_name                       anotherhost1,another2 ; addional servers not in a group
        service_description             Passive-slot1
        check_command                   check_nrpe!md_passive_default
        check_interval                  10080         ; active checks only once every 7 days
        retry_interval                  10080         ; for a non-OK do not retry for 7 days
        passive_checks_enabled          1             ; passive checks any time
        flap_detection_enabled          0             ; disable, places a warning on dashboard
#       active_checks_enabled           0             ; disable active checks, places warning on dashboard
        max_check_attempts              1             ; for non-OK retry N times at retry_interval
                                                      ; max_check_attempts cannot be 0
        notification_interval           10080       ; cannot be less than check interval
        }

  Notes: server side script uses "nc" (netcat) to listen for requests, yes I
       am aware BASH has full tcpip support on Linux and could run as a full
       multithreaded server program; but I want it to be portable. Using 'nc'
       means this is not suitable for lots of updates posted in a short period.
 
----------------------------------------------------------
--- useful generic nagis/nrpe check scripts            ---
----------------------------------------------------------

[1] ============= md_check_last_patching_date ============
    History:
       My VM farm had got to the point I was losing track of what was 
       being updated regularly as I had quite a few I needed to stay running.
       This was implemented as a reminder.

    Will (as coded) raise a warning if a server has not been patched in the
    last 20 days, a critical if not patched in 30 days. The values are
    coded as constants in the script so easy to change; I do not allow
    parameters to be passed ('dont_blame' disabled in my setup) but you can
    change that if you want.

    Check script is designed to be generic, I use this one script on the following OS's
    - rhel family (if rhel expects dnf, will try fallback to apt if dnf not found)
      used on Fedora33, Rocky8, Alma9 
    - debian (if debian expects apt)
      used on Debian12 and Debian13 
    - SunOS (expects pkg)
      used on Openindiana 

    This is mainly here as a howto (or at least how I do it) to check when the
    last date a server was patched.

   nagios/nrpe simple config
       in a file under directory nrpe.d you would have additional commands defined
       !!! this example is for Debian (rhel uses lib64 not lib, openindiana probably /usr/local/nagios/libexec)
          command[md_check_last_patching_date]=/usr/lib/nagios/plugins/md_check_last_patching_date
       in your nagios main config you would have something like the below,
       NOTE: I have the check interval at 12 hours, this is not a check you want running
             at the default every 5mins interval as it is not going to change often
define service{
        use                             local-service         ; Name of service template to use
        hostgroup_name                  all-linux-hosts
        host_name                       jellyfin,openindiana
        service_description             Last package updates
        check_interval                  720           ; active checks only one every 12 hours
        check_command                   check_nrpe!md_check_last_patching_date
        notification_interval           720         ; cannot be less than check interval
        }

[2] ================= md_check_timesync =================
    History:
       There are existing plugins to check NTP, but I wanted a common one
       that handled both ntpd and chronyd. I was using the provided NTP check
       plus a seperate custom service check for servers using chrony; but
       decided I wanted just one service for timesync checks and the plugin
       should figure it out.
       This has only been tested on Linux servers and not yet
       on openindiana [as I have network/ntp disabled there until I
       figure out its quirks, currently ntpq there just returns
       no association ids found (configured to use one of my servers)]
       * As openindiana uses ntpd it should just work there as well, but
         command output may be different so I may still have to handle
         that. 
       * Also intend to test and if needed update to include FreeBSD at some point.

   nagios/nrpe simple config
       in a file under directory nrpe.d you would have additional commands defined
       !!! this example is for Debian (rhel uses lib64 not lib, openindiana probably /usr/local/nagios/libexec)
          command[md_check_timesync]=/usr/lib/nagios/plugins/md_check_timesync
       in your nagios main config you would have something like the below,
define service{
        use                             local-service         ; Name of service template to use
        hostgroup_name                  all-linux-hosts
        service_description             Last package updates
        check_command                   check_nrpe!md_check_timesync
        }

[3] ================ more to follow ? ===================
    most of my service checks also have event handlers and lots of
    sudoers entries to fix issues found so could be tricky to make
    generic.
