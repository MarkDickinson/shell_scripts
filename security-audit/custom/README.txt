This directory contains the customised rules for each unique server.

If there is no unique customisation file for a servername then the processing script will
fall back to the default ALL.custom file; this file must exit to provide a fallback.

The naming of customisation files must be servername.custom
   servername must be the unqualified servername (ie: mywebserver.example.com wpuld be mywebserver)
   custom must be the suffix appended to the filename
   so the customised rules file in this example would be mywenserver.custom

Most files would be a set of include lines from the custom_includes directory
with only individual serve rtweaks needed in unique server files.
Refer to the example-X.custom files.
