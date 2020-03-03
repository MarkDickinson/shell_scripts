Security Audit Toolkit - FOR LINUX SERVERS

Purpose: check for common security issues on multiple Linux servers 
         and produce a 'global' report of security status

Upgrade Notes: whenever upgrading between versions of this toolkit the
               new version of the data collection script should be
               run on all servers and a full processing run be performed
               on the reporting server. This is required to ensure any
               new data fields required by the new version of the processing 
               script are present.

History: I have quite a few Linux servers now, and need to make sure they
         and any new servers I build remain secure.
         while tools like puppet/chef/ansible are great at ensuring packages
         are installed and their configuration files managed properly when
         packages are installed they tend to also create a lot of supplementary
         files (doc, man and install/admin scripts for example) that are
         seldom checked for security.
         There are also the traps with deleting users, are they also removed
         from the ftpusers file ?, are any existing crontab files removed ?.
         And lots of other things that should be checked on new server builds
         such as defaults for passwords etc that are normally just set and
         forgotten and not managed by configuration tools.
         So I created this, and am continuously updating it as needed.

Usage:   The collection script is run an all servers and the output files
         copied to a single 'reporting' server.
         On the reporting server run the processing script, it will generate
         a top level index with all server summaries and the normal links to
         drill-down to individual servers and into the problems found.
         -- Documentation is in the file security-audit-doc.html --

Requirements: (1) only runs on Linux servers [tested on Fedora/CentOS/Kali]
              (2) required 'fuser' installed on all the server in order
                  to obtain information on what processes are using network
                  ports and sockets [optional but if not present on the
                  server report fields will be blank and some network 
                  options in the server customisation file cannot be used]
              (3) 'dmidecode' and 'lshw' need to be installed on each
                  server if you intent to also capture hardware information
                  [optional but if not installed the hardware details page
                  of the report will just state that they were not installed]
              (4) A LOT OF PATIENCE as a full scan of a server can produce
                  well over 300,000 files to be checked which can take a
                  very long time, combine that with a full processing run
                  of 20-30 servers you will have to wait a few days.
                  (refer to the documentation for single server processing
                  and doing limited data collection scans instead of full scans).

Current status: 
  * filesystem checks - checks the permissions of all 'system files' to ensure
    they are only writeable by the file owner, and that all are owned by a 
    valid defined 'system' userid. System files are defined as all those
    under directories /bin /boot /dev /etc /lib /opt /sbin /sys /usr /var,
    easy to add others (search in collection script on the string
    find_perms_under_system_dir and copy/paste and existing line to
    add a new directory if needed).
  * cron checks - check all crontab files belong to users that exist on the
    server and that the settings in cron.allow or cron.deny permit the user
    to use cron... also attempt to identify the file permissions of each
    script run by cron to ensure it is only writeable by the crontab owner
    (amazing the number of script files run by root via cron that anyone
    can update) but that does require cron is used to run scripts, crontab
    commands that are 'stacked' with a ; and start with system utilites
    such as "cd /somedir;./somecommand" will always alert as obviously
    users do not own 'cd'.
  * checks for common things such as a valid motd and ssh banner existing,
    permitrootlogin set to no in the sshd config etc.
  * user checks - uuids are all unique, all users have a password or
    account is locked, all user home directories exist and are secured correctly,
    report on all users that can use ftp (not in ftpusers file) and on all
    users in the ftpusers file that no longer exist on the server, check
    security of /etc/shadow, and of course checks the system default settings
    for password length and expiry.
  * network connectivity checks - ensures every open port on the server is
    documented in the customisation file for the server, alerts on undocumeted
    ports. For documented ports raises warnings if the application is 
    listening on all interfaces instead of being securely configured to 
    listen only on explicit interfaces. Also alerts on any ports defined in
    the server customisation file that are no longer in use so the config 
    file can be cleaned up.
  * customisation files can be configured for servers to allow for known
    exception cases; such as files that must be insecure, network ports for
    applications that just cannot be configured to specific interfaces,
    user home directories that must be insecure (ie: multiple system users
    are mapped to /bin or /sbin which must be owned by root (not by the
    system user such as adm or operator) and must be traversable by other
    users, and quite a few other customisable cases.

Files provided:
   collect_server_details.sh   - run on all server to collect details to be processed
   process_server_details.sh   - run on reporting server to process above files
   security-audit-doc.html     - documentation
   ALL.custom                  - default customisation file example (used if no server.custom)
   phoenix.custom              - example overriding the default ALL.custom for server 'phoenix'

Directories that must exist (at no point in the directory path can a underscore ( _ ) be used
   somedir                     - location of the two scripts
   somedir/custom              - place all custom files in here
   somedir/results             - all reporting results are placed here
 - the collection script output file directory and archive directory are
   parameter supplied, the sample RUN script expects them to be under
   the somedir path also.

