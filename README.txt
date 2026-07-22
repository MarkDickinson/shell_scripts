Created to store some shell scripts I do not wish to lose track of.
May be useful to others. May not be.

The main directory is general scripts.
   - makepdf.sh  
        pipe a text file into it and get output as a pdf file

   - common_functions.bash
        a work in progress, effectively a placeholder


Any subdirectories will be task specific scripts.
   - security-audit : scripts for security auditing RHEl based linux servers,
                      and now Debian as well as I'm moving that way. Does
                      its best to handle both iptables and firewalld/netfilter
                      as depending on server function I could use either.
                      All bash, not performance efficient.
   - calendar-creator : used the linux "cal" program to pull out the values
                      to populate dates in a html calendar, inserts pictures
                      for each month from a list provided, allows holidays
                      and bithdays to be inserted into day boxes.
                      This is a cgi webserver script, you could run it as a standalone
                      script to create a html file and file-open that if you do
                      not have a webserver; you need to use your browsers
                      print function to print it however as the browser does
                      the formtting based on the html.
