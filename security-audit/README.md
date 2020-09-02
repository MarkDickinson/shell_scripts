# Linux Server Audit Toolkit

These scripts Check for common security issues _on Linux Servers_ not normally checked on a regular
basis by system administrators. It is designed for Fedora/CentOS/RHEL servers although with a few
exceptions works perfectly well on debian based servers like Ubuntu and Kali.

Using the scripts the checks can be automated to provide one place check results can be viewed.
Additionally automating the processing runs allows you to periodically archive the processing results (an
option of the processing script) to provide historical snapshots of things such as all cron jobs on a server
or all processes that have opened listening ports on the server.

For known exceptions customisations can be done to the checks performed on a per-server basis.
Detailed documentation on all the customisation parameters available is in the file file security-audit-doc.html.

Be warned, the fisrt run against a server will most likely find hundreds of issues to be resolved.
But it is possible to get them down to only a few warnings (there will probably always be warnings) and
I even have a few servers with zero alerts now.

## Table of contents
* [Requirements](#requirements)
* [Security issues](#security-issues)
* [Current checks performed](#current-checks-performed)
* [Processing control features](#processing-control-features)
* [Directories that must exist for processing](#directories-that-must-exist-for-processing)
* [Example install using required directories](#example-install-using-required-directories)
* [Using the scripts](#using-the-scripts)
* [Example of the main index produced from processing](#example-of-the-main-index-produced-from-processing)
* [Known issues with the current release](#known-issues-with-the-current-release)
* [Planned enhancements](#planned-enhancements)


## Requirements
* MUST have the BASH shell on all servers, the scripts use operations only available in bash 
* processing scripts must be installed under a directory path that contains no underscore ( _ ) character, that is used as a parsing delimiter
* only runs on Linux servers [tested on Fedora/CentOS/Kali/Ubuntu]
* the 'netstat' command must be available on all the servers and must support the '-p' option, for collecting information
  on tcp/tcp6/udp/udp6/raw/raw6 ports and the unix sockets open on the server and what is using them
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

## Security issues

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
  alerts for docker/overlay2 and snap/core* suid files as these are pretty
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
  obsolete server firewall rules)
* reports on all orphaned files and directories
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
* runtime processing parameter to allow a single server to be re-processed as needed
* runtime processing parameter to allow automatic detection of updated collected data files and process them
* NOTE HOWEVER automatic re-processing of all servers is forced/performed if a new version of the processing script is installed

## Directories that must exist for processing

The below directory structure is expected for the processing script to work. 
If obtained using git clone the directory structures will be in place.

```
   somedir                    - the root of where you install the toolkit
   somedir/bin                 - location of the processing script (expected by example RUN file)
   somedir/custom              - place all custom files in here
   somedir/results             - all reporting results are placed here
 - the directory containing the data to be processed that was collected by the
   collect_server_details.sh script must be supplied by parameter
   (I prefer somedir/rawdatafiles)
- any result archive directory must be parameter supplied
   (I prefer somedir/archive)
```

## Example install using required directories

As this toolkit is bundled under my shell scripts package these are the steps
needed to install the toolkit and cleanup unused files.
_You cannot_ leave it in the cloned directory as the underscore in the shell_scripts
directory name will prevent the processing script running correctly.

```
cd /some/app/dir/you/use
git clone https://github.com/MarkDickinson/shell_scripts.git
cd shell_scripts/security-audit
mkdir bin custom results archive rawdatafiles
mv *sh bin
mv ALL.custom custom
cd ../..
rm README.txt common_functions.bash makepdf.bash nagios_submit_passive_update.sh
cd ..
mv shell_scripts/security-audit .
rmdir shell_scripts
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

* optional processing runtime parameter '--indexkernel=yes' will add an extra field to the
  index listing the kernel version reported by 'uname' on the server that was processed
  (tip: can be used in conjunction with '--indexonly=yes' to switch that extra column on/off
  without any server processing)
* if new collector data files are available they will be shown as ready to be processed
* if any server collected data files are over two weeks old they will be highlighted for easy visibility,
  as you should have automated data collection and getting it to the processing server
* the values in the server name field are links to individual server results indexes,
  which in turn have links to details on each check performed for the server

## Known issues with the current release
* Nowhere in the directory path of the processing script can there be an underscore</b> ( _ )
  character used, the underscore character is used by the script for parsing and having it
  in the directory path will cause problems. Not really an issue, just do not do it
* if you ^C or kill a running processing scriot the lockfile remains, you must use the
  processing script --clearlock option to remove it
* cron job checks - only cron jobs have securiry permissions checked, not anacron files
  or any queued 'at' jobs
* cron job checks - stacked commands are able to be tested if seperated by ';' '&&' '|',
  the '||' syntax is not supported yet.
* cron job checks - where a cron job uses a system command (echo, cd, php) rather than
  a discrete script an alert will normally be raised as system commands are normally owned
  by root and not the owner of the cron job. A list of commands considered to be non-disruptive
  can be used to suppress alerts for things like 'echo', 'php', 'bash' etc. to allow those
  to be used without alerting; although commands such as 'ls', 'cd', 'find' etc. will
  always alert as there is no way of determing what environment a stacked crontab command
  line has obtained if it is using combinations of these. These are 'hard coded' in the
  collection script (as custom files are used only by the processing script which runs on
  a seperate server so cannot be used by the collection script). If you wish to alter the
  defaults search in the collection script for CRON_CMD_IGNORE_LIST, CRON_CMD_SHELL_LIST,
  CRON_CMD_FATAL_LIST strings and update those
* user checks - system defaults for max password length and expiry checks are
  obtained from /etc/login.defs; An uncommented minlen value is also searched for in pwquality.conf
  and any files in the pwquality.conf.d directory as PAM systems would use this in preference
  on Fedora/CentOS/RHEL systems. _On Ubuntu servers comments in login.defs indicate minlen
  is set in files in /etc/pam.d but as I can find no examples of this Ubuntu servers will
  always raise an alert saying minlen is 0_ which as I don't use Ubuntu other than testing
  this script so am unlikely to spend time resolving.
  Commented values would be ignored so ensure they are set. authconfig is depreciated on fedora in favor of authselect
  and god knows what tools ubuntu use so as every system will have different management tools
  cannot use those to query values so rely
  on values set in the files _and ignore commented defaults_ as defaults change
* server firewall rule checks - no attempt is made to follow firewall chains or determine zones,
  any rule to open a port is considered an open port
* servers running NetworkManager will have firewall ports opened that users may not expect,
  _This is not an issue with this toolkit_ but
  with a lack of control over what NetworkManager decides to open; prior to version 0.12 any
  firewall accept rule for a port not in use alerted as an obsolete firewall rule, from
  0.12 onward a custom file rule can be used to identify and downgrade alerts to warnings for ports opened
  by NetworkManager rather than ports you explicitly configured.
  Examples: 'firewall-cmd --list-ervices' shows 'cockpit dhcpv6-client dns http ntp ssh' and
  'firewall-cmd --list-ports' does not show the following ports,
  but the following ports have firewall rules opening the ports, udp 67(/usr/lib/firewalld/services/dhcp.xml),
  udp 68(/usr/lib/firewalld/services/RH-Satellite-6.xml),udp 69(/usr/lib/firewalld/services/tftp.xml);
  _and worse_ some processes that use dynamic ports will occasionally use those ports so unexpected apps are exposed
* BUG: when processing a capture with a large number of files _SOMETIMES_ an error is thrown
  "bin/process_server_details.sh: line 4422: ----------------------------------: command not found"
  which is not the contents of line 4422. A rerun with no changes does not have the same issue.
  Ocurrence is completely random so hard to track down. Does not affect any results produced
* Only handles simple firewall rules. Does not handle complex firewall rules such as the
  iptables entries below 

```
multiport dports 8773,8774,8775,8778 /* 001 nova api
multiport dports 5900:5999 /* 001 nova compute
multiport dports 16509,49152:49215 /* 001 nova qemu
```

## Planned enhancements

No planned enhancements at this stage. Scope creep was setting in and I was
starting to add checks for silly things that were more server monitoring
than security/audit related so I have decided to hold off on future changes
until I find more security specific checks that _need_ implementing.

Any releases in the newxt few months will be bugfix, if any are found to correct.

