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
} # end of extract_parm_value



