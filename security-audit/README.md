# Linux Server Audit Toolkit

No Guarantees that these are fit for purpose in your environment.

YOU SHOULD NEVER RUN UNKNOWN SCRIPTS AS ROOT. The collector script needs to run as root so
unless you are happy to look through thousands of lines of bash script to make sure it will
not damage your machines you should not use this.

These scripts Check for common security issues _on Linux Servers_ not normally checked on a regular
basis by system administrators. It is designed for Fedora/CentOS/RHEL servers although with a few
exceptions works perfectly well on Debian based servers like Ubuntu and Kali.

Using the scripts the checks can be automated to provide one place check results can be viewed.
Additionally automating the processing runs allows you to periodically archive the processing results (an
option of the processing script) to provide historical snapshots of things such as all cron jobs on a server
or all processes that have opened listening ports on the server.

For known exceptions customisations can be done to the checks performed on a per-server basis.
Detailed documentation on all the customisation parameters available is in the file file security-audit-doc.html.

Be warned, the fisrt run against a server will most likely find hundreds of issues to be resolved.
But it is possible to get them down to only a few warnings (there will probably always be warnings) and
I even have a few servers with zero alerts now.

Mostly useful after you have quietened down the initial noise is to see what annoying
things package updates do to your servers, things like user cockpit-wsinstance becoming
cockpit-ws, identifying new users that may have been created when new packages are 
added (ok in this case by reporting a user is not in ftpusers), lets you know what new
suid files have been created or expected ones deleted,
firewall rules having a port open when nothing is listening or something unexpected
listening on a port... and basically lots of stuff that will show up, after you
have qietened down all the issues from a first run.

These scripts are _slow_ to run and cpu intensive as they are bash shell scripts.


## Table of contents
* [Requirements](#requirements)
* [Security issues with using this toolkit](#security-issues-with-using-this-toolkit)
* [Current checks performed](#current-checks-performed)
* [Processing control features](#processing-control-features)
* [Directories that must exist for processing](#directories-that-must-exist-for-processing)
* [Using the scripts](#using-the-scripts)
* [Example of the main index produced from processing](#example-of-the-main-index-produced-from-processing)
* [Planned Enhancements](#planned-enhancements)


## Requirements
* MUST have the BASH shell on all servers, the scripts use operations only available in bash 
* processing scripts must be installed under a directory path that contains no underscore ( _ ) character, that is used as a parsing delimiter
* only runs on Linux servers [tested on Fedora/CentOS/Kali/Ubuntu]
* the 'netstat' command must be available on all the servers and must support the '-p' option, for collecting information
  on tcp/tcp6/udp/udp6/raw/raw6 ports plus the unix sockets open on the server and what is using them. where the
  netstat version supports it active bluetooth connections (if you have a wireless card in the server) are also
  collected and reported on
* the 'iptables' command should be available on all servers, for checking iptables firewall rules against open ports
* the 'nft' command should be available on all servers, for checking netfilter firewall rules against open ports
* both 'dmidecode' and 'lshw' should be installed to record the server hardware details
* A LOT OF PATIENCE as a full scan of a server can produce
  well over 300,000 files to be checked which can take a
  very long time, combine that with a full processing run
  of 20-30 servers you will have to wait a few days.
  (refer to the documentation for single server processing
  and only 'updated' server processing to minimise the time
  needed) and you can of course perform limited file checking
  by using the --scanlevel on data collection scans instead of
  the default of full scans).

## Security issues with using this toolkit

The data collection script collects a lot of information from each server,
including such things as the contents of /etc/passwd and firewall port
information.

As such when copying
the collected datafile to the processing server ensure you use an encrypted
protocol such as scp or sftp and not something like rsync.

The processing server should also be tightly controlled, with a minimum
of users permitted to view the data files.

Also access to view the output should be controlled as the report is
designed to highlight issues that could be exploited.

The collection script must run as the 'root' user in order to have access
to obtain all the information it needs; as such ensure you have a trusted
copy of the data collection script and review it to ensure you trust it
before running it. You obviously _should never run untrusted scripts as root_
so feel free to look at my really bad coding (getting worse as I try and insert
more things into it) before running the collection script.

The processing script should not run as root, it needs no special privs.

## Current checks performed
* filesystem checks - checks the permissions of all 'system files' to ensure
  they are only writeable by the file owner, and that all are owned by a 
  valid defined 'system' userid. System files are defined as all those
  under directories /bin /boot /dev /etc /lib /opt /sbin /sys /usr /var,
  easy to add others (search in collection script on the string
  find_perms_under_system_dir and copy/paste and existing line to
  add a new directory if needed). The default list of users that can own
  system files can be expanded using custom file parameters
* filesystem checks - report on all suid files that are not explicitly defined
  in the customisation file as being permitted/expected to exist (reports
  on all suid files but only alerts on unexpected ones). Notes: can suppress
  alerts for docker/overlay2 and snap/core\* suid files as these are pretty
  much randonly placed for every docker container and snap application, but
  they are still listed in the report for review
* read only files checks (additional for my use) - checks all files under explicitly
  defined filesystem paths have 'read-only' permissions (for static or seldom
  changing web served pages). Filesystem paths are provided by a file selected
  with the optional collector option --webpathlist=/some/file and if not
  provided (default) data for those checks will not be collected and the
  report not produced... most users will never use this but I need it
* cron checks - check all crontab files belong to users that exist on the
  server and that the settings in cron.allow or cron.deny permit the user
  to use cron... also attempt to identify the file permissions of each
  script run by cron to ensure it is only writeable by the crontab owner
  (amazing the number of script files run by root via cron that anyone
  can update) but that does require cron is used to run scripts, crontab
  commands that are 'stacked' with a ; and start with system utilites
  such as "cd /somedir;./somecommand" will always alert as obviously
  users do not own 'cd'
* check at.allow and at.deny as well to identify who can use at/batch
* checks for common things such as a valid motd and ssh banner existing,
  permitrootlogin set to no in the sshd config etc.
* user checks - uuids are all unique, all users have a password or
  account is locked, all user home directories exist and are secured correctly,
  report on all users that can use ftp (not in ftpusers file) and on all
  users in the ftpusers file that no longer exist on the server, check
  security of /etc/shadow, and of course checks the system default settings
  for password length and expiry
* network connectivity checks - ensures every open port on the server is
  documented in the customisation file for the server, alerts on undocumeted
  ports. For documented ports raises warnings if the application is 
  listening on all interfaces instead of being securely configured to 
  listen only on explicit interfaces. Also alerts on any ports defined in
  the server customisation file that are no longer in use so the config 
  file can be cleaned up
* firewall rule checks - if the server has a firewall in place will check
  (if the iptables command (or nft for netfilter servers) is on the server)
  all explicit port numbers used match ports expected to be open on the
  server as defined by the network checks, and also alert if firewall rules
  accept traffic to ports that are not in use on the server (to identify
  obsolete server firewall rules). At this time ipfilter checks are not 
  implemented (ie: will not do firewall checks for SunOS).
* filesystem checks - reports on all orphaned files and directories (those
  not owned by an existing user). This report 'appendix J' is only
  produced if orphans were found
* checks for common unsafe sudoers configuration entries
* optional, backs up /etc
* optional (but default) collect hardware info
* optional, if 'rpm' is available collect a installed package list

## Processing control features
* customisation files can be provided at a per-server level for known 
  exception cases; such as files that must be insecure, network ports for
  applications that just cannot be configured to specific interfaces,
  user home directories that must be insecure (ie: multiple system users
  are mapped to /bin or /sbin which must be owned by root (not by the
  system user such as adm or operator) and must be traversable by other
  users, and quite a few other customisable cases.
* runtime processing parameter to allow a single server to be re-processed as needed,
  note however automatic re-processing of all servers is forced/performed if a new version
  of the processing script is installed and you try to process a single server
* runtime processing parameter to allow automatic detection of updated collected data
  files and process only those new ones (intended for batch processing where you
  automate collection of data and provide a few new servers per day)

## Directories that must exist for processing

The below directory structure is expected for the processing script to work. 
If obtained using git clone the directory structures will be in place.

```
   somedir                   - the root of where you install the toolkit
   somedir/bin               - location of the processing script (expected by example RUN file)
   somedir/custom            - place all server custom files in here
   somedir/custom_includes   - shared custom files that can be 'included' in server custom files
   somedir/results           - all reporting results are placed here
 - the directory containing the data to be processed that was collected by the
   collect_server_details.sh script must be supplied by parameter
   (I prefer somedir/rawdatafiles)
- any result archive directory must be parameter supplied
   (I prefer somedir/archive)
```

## Using the scripts

Full details on all runtime parameters that can be passed to the scripts are 
in the file security-audit-doc.html. You should review that file as there
are many optional parameters that can be used in the commands below.

On each server to be checked run the data collection script

```
./collect_server_details.sh [--scanlevel=N]
```

The files produces by the collection script need to be copied to a directory
on the processing server. As noted in the required directories list above
I prefer this to be under the main directory in a directory named rawdatafiles.

Once you have a bunch of servers data ready to process, on the processing server

```
bin/process_server_details.sh --datadir=/where/you/put/the/server/datafiles
```

The results will be in the results directory, the toplevel is index.html.

Look at the file RUN for examples of all available processing script options.


## Example of the index produced from processing

![Main Index Page](./readme_images/main_index_example.png)

Most fields are self explainatory, requiring a mention are the points below

* the values in the server name field are links to individual server results indexes,
  which in turn have links to details on each check performed for the server
* the alerts field will have text in green if OK and red if not, note fields in green
  that have alerts have a (N) column also which is the number of expected (never to be fixed)
  alerts as coded as descriptions in the server customisation file and a link to the description
  of all alerts expected, exact match to actual alerts for it to be considered acceptable
* if new collector data files timestamped more recenly than the last processing for that server
  are available they will be shown as 'New data ready' in the warning color
* if any server collected data files are over N days old they will be highlighted in the alert
  color for easy visibility, as you should have automated data collection and getting it to the
  processing server, default is 14 days before considered obsolete but may be overidden on a per
  server basis with number of days actually configured in the custom file as (N) shown after the
  snapshot date

## Planned Enhancements

This will not affect most of you, but on servers running OpenStack it generates a
lot of complicated firewall rules such as 'dports nnnn,nnnn,nnnn:nnnn,nnnn (yes,
a range can be imbedded in a list as well as unique ports). To complicate even
further 'dports' is used in iptables with a : range seperator and 'dport' in netfilter
with a - range seperator.
Complicated rules such as that are not handled in V0.17. Changes to handle some of that
were implemented into V0.18 but it is still a work in progress.

I have an OpenIndiana VM I fire up occasionally, so support for processing SunOS
data collection is partially implemented fom version 0.23 and will be ongoing
(as a low priotity when I get time).

And anything else I think of as time goes by.
