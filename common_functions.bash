# =========================================================================
# Library that can be sourced into bash scripts.
# Routines that are common across many of my scripts, that are not
# specialised enough to go into custom libraries.
#
# The intent is that where possible only bash is used (no spawning of
# subtasks like grep and awk unless absolutely necessary).
#
# To be included here a function must be used in at least three of my
# internal scripts.
# =========================================================================

# -------------------------------------------------------------------------
# extract_parm_value: search for a keyword and value within a string
# input parms - 
#          parm1         : a key to search for
#          parm2-infinity: a string to search for the key in
# output: the value of the parm
#
# notes: parm and value can be anywhere in the string
#        value can be bracketed wiith " or ' characters
#        if value not quoted within the string word1 after key is the value
#        seperator between key and value can be space, = or :
#
# history:
#    2020/Jun/10 MID - created function as I needed to parse out fields
#                      randomly distributed within a string in a script,
#                      and I will probably need it again so in a library.
#                      My requirement was bash only functions as I did not
#                      want a lot of grepping and awking to get this info.
# -------------------------------------------------------------------------
extract_parm_value() {
   parmkey="$1"
   shift
   datastr="$*"
   if [[ $datastr == *"${parmkey}"* ]];    # can only do parsing if the key exists in the string
   then
      # rest will contain all data after the matched substring
      rest=${datastr#*$parmkey}
      # if pair was key=value or key:value move over the = or :
      testvar=${rest:0:1}
      if [ "${testvar}." == "=." -o "${testvar}." == ":." ];
      then
         rest=${rest:1:$((${#rest} - 1))}
      fi
      # see if value is within " or ' quotes
      testvar=${rest:0:1}
      if [ "${testvar}." == "\"." ];        # IF within " quotes
      then
         rest=${rest:1:$((${#rest} - 1))}      # drop the " so it is not used in the next test
         endchar="\""
         rest=${rest%$endchar*}                # drop all chars after the "
      elif [ "${testvar}." == "'." ];       # ELSE IF within ' quotes
      then
         rest=${rest:1:$((${#rest} - 1))}      # drop the ' so it is not used in the next test
         endchar="'"
         rest=${rest%$endchar*}                # drop all chars after the '
      else                                  # ELSE no quotes so just get first word
         # if we have the extract_words routine use it, otherwise use a temporary word1 routine
         typeset -f -F extract_words 2>/dev/null
         if [ $? -ne 0 ];
         then
            word1() {   
               echo $1
            }
            rest=`word1 ${rest}`
            unset word1
         else
            rest=`extract_words 1 --data ${rest}`
         fi
      fi
   else   # If parmkey is not in the string return an empty result
      rest=""
   fi
   # Display result
   echo "${rest}"
} # ----------------- end of extract_parm_value -------------------

# *********************************************************************
#
# interactive_shell - determine if the script is being run
#                     interactively or from a scheduler such as cron
#
# There are two tests possible to see is a bash shell is interactive
# - one of the settings in $- contains an i
# - the PS1 (prompt) value is not set
#
# Interactive bash shell
#     [mark@phoenix bin]$ echo $-
#     himBHs
#     [mark@phoenix progress_bar]$ echo $PS1
#     [\u@\h \W]\$
#
# Same commands in a shell as below give
#    echo $-
#    echo $PS1
# outputs
#    [mark@phoenix progress_bar]$ bash test_interactive.sh
#    hB
#
#    [mark@phoenix progress_bar]$
#
# >>>>  HOWEVER HOWEVER HOWEVER HOWEVER HOWEVER
#   If the above is used is a script and the script run with
#   'bash scriptname' or ./scriptname they will always report non-interactive.
#  
# What I am loooking for is to determine if to display output if the
# script is running on a terminal by a user or suppress it if the
# script is running under something like cron.
# So lets test if STDIN is in use, it will not be if run under cron.
# (note to self: it probably will be open if run under my job scheduler,
#  have to test that as testing STDIN may also be insufficient)
# - The below reports as interactive if run with the ./scriptname
#    if [[ -t 0 ]]; then
#       echo "Running interactive"
#    else
#       echo "Running non-interactive"
#    fi
# - run from cron as /dirname/scriptname it reports as non-interactive
# So this test seems more suited.
#
# RETURNS
#    1 - running interactive (with a STDIN)
#    0 - not interactive (STDIN closed or /dev/null)
#
# *********************************************************************
interactive_shell() {
   if [[ -t 0 ]]; then
      echo "1"          # interactive
   else
      echo "0"          # non-interactive
   fi
} # ----------------- end of interactive_shell -------------------

# *********************************************************************
# routine: progress_bar
# 
#  Displays a progress bar. 
# 
#  Parameters
#        1 - current item number being processed
#        2 - total number of items to process
#
#  Example usage
#       max_items=50
#       for ((i = 0; i < max_items; i++)); do
#	     progress_bar "$((i + 1))" "${max_items}"
#            # do some processing that produces no output that
#            # would cause the progress bar to move to a new line
#            # or it would not look right.
#            sleep .5     # for the example or it would run too fast
#	done
#       echo ""    # so next output line is below the progress bar
#
# Common color and style codes include:
#
#    Text Colors (Foreground):
#        30m Black
#        31m Red
#        32m Green
#        33m Yellow
#        34m Blue
#        35m Purple (Magenta)
#        36m Cyan
#        37m White 
#    Background Colors: Add 10 to the foreground color code (e.g., 41m for red background).
#    Text Styles:
#        0m Reset all attributes
#        1m Bold
#        4m Underline
#        5m Blinking (may not be supported by all terminals)
#
#    CREDITS: Based upon the code covered in
#             https://www.youtube.com/watch?v=U4CzyBXyOms
#     channel https://www.youtube.com/@yousuckatprogramming
#
# *********************************************************************
progress_bar() {
   # if this routine is used inside a cron job it could result in
   # thousands of lines of output; so if STDIN is not attached to a
   # terminal just return immediately.
   if [[ ! -t 0 ]]; then
	   return
   fi

	local current=$1                 # current item number
	local len=$2                     # number of items
	local pct_done=$((current * 100 / len))
	local i;
	local bar_char=" "      # space, we set background to show progress bar
	local empty_char="."
        local disable_pct_display="NO"   # if colums too small to display pct test we will disable it

	# adjust bar to fit window width
	if [ "${COLUMNS}." != '.' ];      # if the shell has set the variable use it
	then
           local length=${COLUMNS}
        else
           local length=$(tput cols)      # else use tput to find the width of the terminal
	fi
	if [ ${length} -gt 40 ];
	then
		length=$((length - 20))     # leave room for count+pct at the end
        else
		disable_pct_display="YES"
	fi
	local num_bars=$((pct_done * length / 100))

	s='['      # start with open bracket
        for ((i = 0; i < num_bars; i++)); do
#		s="${s}${bar_char}"
		s="${s}\e[42m${bar_char}\e[0m"   # colour green for bar
	done
        for ((i = num_bars; i < length; i++)); do
		s="${s}${empty_char}"
	done
	s="${s}]"     # end with close bracket
	if [ "${disable_pct_display}." == "YES." ];   # too small to display counts+pct
	then                                          # yes, do not display that info
           echo -ne "${s}\r"
        else                                          # not too small, room to display it so do so
           echo -ne "${s} ${current}/${len} ${pct_done}%\r"
	fi
} # -------------------- End of progress_bar routine --------------------
