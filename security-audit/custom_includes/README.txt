This directory contains rules that are common across all servers or applications.

They would be included in custom/seerver.custom files with lines like
INCLUDE ../custom_includes/filename

This keeps server custom files small and rules for common applications
do not have to be manually coded in each server custom file.

TODO
One day split into rhel and debian directories so I do not have to keep putting _debian
on the ones I have to change to fit that; will just make the files in this directory
more sensible.
Maybe leave shared ones that work for both here, or in a 'common' subdir but that could
be even more confusing in the long run.

