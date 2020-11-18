This directory contains the default ALL.custom that will be used for all servers that do not
have an explicit servername.custom file assigned.

It is also the location where all servername.custom files must be placed when creating
server specific customisation files.

The naming of customisation files must be servername.custom
   servername must be the unqualified servername (ie: mywebserver.example.com wpuld be mywebserver)
   custom must be the suffix appended to the filename

Example files:
   ALL.custom is an example of a default file
   puppet.custom is an example of a server specific file for Fedora 32
   ubuntu-test.custom is an example of a server specific file for Unbuntu 20.04
