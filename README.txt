Created to store some shell scripts I do not wish to lose track of.
May be useful to others. May not be.

The main directory is general scripts.
   - makepdf.sh  
        pipe a text file into it and get output as a pdf file
   - nagios_submit_passive_update.sh
        submit nagios passive updates 

   - common_functions.bash
        a work in progress, effectively a placeholder


Any subdirectories will be task specific scripts.
   - security-audit : scripts for security auditing RHEl based linux servers,
                      and now Debian as well as I'm moving that way. Does
                      its best to handle both iptables and firewalld/netfilter
                      as depending on server function I could use either.
                      All bash, not performance efficient.
   - demo-web-apps  : best to avoid. A long time ago I wrote a tutorial on
                      prototyping web apps using nothing but bash. That
                      comes with the disclaimer you should never put those
                      on a server with a public facing interface
