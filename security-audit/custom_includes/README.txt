This directory contains 'include' rules for applications you may have installed.
This allows servers with common applications to just include the rule file rather
than having to repeatedly code the same rules in each individual servers customisation
file.

In a server customisation file you would normally have an include for the base OS
and then includes for each application
(system as well as application, ie: chrony or ntp do not belong in a server_ file
 as two servers with the same base OS could use different choices for time sync).

SAMPLES: of server custom files are in the "custom" directory.

IMPORTANT: the order of includes is important. If muliple files contain a
           identical parameter only the value in last included file will be used.

---- Server defaults ----
There is a base default rule set for servers I have named "server_<ostype>" that
can be used as the fisrt include in any custom file which will (almost) work as
a template for any base server OS install.
Note1: the (almost) is because I recently built a couple of servers that do not
      need cockpit; the server_<ostype> files expect it to be there as I have
      only recently needed servers without it; I still need to split that out.
      The result is their are alerts for the custom file referencing ports and
      userids that do not exist (as what is in the custom file is checked against
      what is on actually the server as an aid to keeping the custom files clean).
      There may be other gotchas like that where I always have something installed
      that you may not.

---- Application examples ----
As different servers will have different applications installed, and some servers
will have applications that also exist on other servers; and I got sick of copy/pasting
between custom files, this custom_includes directory also contains rules for applications.
* Important Note: some of them end with _debian; that is because in migrating some of my
  machines from RHEL family OS to Debian I discovered... well rules fopr one OS will not
  work for another, they are all different.

You should create your own for applications you use.
The examples here should be used with a grain of salt, as they will not work on all installations
You will probably have to customise them.

---- examples of issues requiring rule changes in the past ----
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
          if used on a fresh C8 install. I do not intend to update the example include file here as with a single
          exception all my CentOS servers have been either moved to Alma or Debian.

  And I have found using different point versions of install media also produce different default packages
  installed.

Recomendation:
  Obviously try them to see if they meet your needs, and customise if not. The server_* include files
  should only have entries removed (and moved to another include file as needed) to ensure the main
  file is usable on all servers of that flavor.
