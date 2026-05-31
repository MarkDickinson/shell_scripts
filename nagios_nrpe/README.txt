I have dozens of site specific NRPE check scripts which are pointless here.

But I also have a few 'generic' ones for things not yet available
out-of-the-box that may be useful; as long as you remembert I run them 
all using NRPE.
They are all BASH scripts.

--- using passive checks ---
History:
   Nagios allows service check status to be updated by manually writing
   updates to its command pipe; which is only really useful on the server
   running nagios itself.
   I wanted remote servers to be able to post updates, so wrote a script
   to make that possible. I have a few 'passive' services defined for
   some monitored hosts that those remote hosts can post crit|warn|ok updates to.

Scripts are
   md_passive_default  
       - the service needs a script to run on periodic checks, this just returns OK
   nagios_submit_passive_update.sh  
       - (a) script runs on nagios server to accept posts from remote servers
             and write to nagios command pipe
             note: hoe to run this as a systemd service is in the script comments
         (b) script can be run on remote servers to post messages to (a)

Notes: server side script uses "nc" (netcat) to listen for requests, yes I
       am aware BASH has full tcpip support on Linux and could run as a full
       multithreaded server program; but I want it to be portable.
         
--- useful generic nrpe check scripts ---
[1] md_check_last_patching_date
    History:
       My VM farm had got to the point I was losing track of what was 
       being updated regularly as I had quite a few I needed to stay running.
       This was implemented as a reminder.

    Will (as coded) raise a warning if a server has not been patched in the
    last 20 days, a critical if not patched in 30 days. The values are
    coded as constants in the script so easy to change; I do not allow
    parameters to be passed but you can change that if you want.
    - supports rhel family [dnf], debian [apt], and also sunos (openindiana) [pkg] 

    This is mainly here as a howto (or at least how I do it) to check when the
    last date a server was patched.

[2] more to follow ?, most of my service checks also have event handlers
    to fix issues found so could be tricky to make generic.
