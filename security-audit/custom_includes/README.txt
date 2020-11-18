This directory contains 'include' rules for applications you may have installed.
This allows servers with common applications to just include the rule file rather
than having to repeatedly code the same rules in each individual servers customisation
file.
You should create your own for applications you use.

The examples here should be used with a grain of salt, as they will not work on all installations
You will probably have to customise them.

examples of issues -

  C7 servers that had puppet agent installed that were upgraded to C8 retained the 'puppet' userid added on a C7 install.
  C8 servers build from scratch that then had the puppet agent installed do not get a 'puppet' userid created
  Result: using the puppet_agent' include file will raise an alert on C8 servers built from scratch as no 'puppet' user.
  Notes: other user changes are affected as well, for example there is no 'rpc' user by default on a C8
         install, but it is on all servers upgraded from C7. You will probably need a seperate server_OSname
         global default include for fresh install and upgraded servers.

  C7 servers upgraded to C8 have considerably less setuid files than a fresh C8 install, for example C8 by default
  installs things like chsh/chfn (util-linux-user package) which where not installed by default on C7 so are also
  not installed on an upgrade from C7 to C8. There are other packages as well as the example that cause issues.
  Result: using the server_CentOS8 include file will produce a lot of unexpected setuid file alerts
          is used on a fresh C8 install. I do not intend to update the example include file here as with a single
          exception all my CentOS servers have been upgraded rather than fresh installed.

  And I have found using different point versions of install media also produce different default packages
  installed.

Recomendation:
  Obviously try them to see if they meet your needs, and customise it not. The server_* include files
  should only have entries removed (and moved to another include file as needed) to ensure the main
  file is usable on all servers of that flavor.
  And personally I am aggressivly using puppet to remove packages that default installs think I need
  to try to get all my servers as identical as servers performing different functions can be.
