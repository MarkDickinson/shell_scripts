#!/bin/bash
#
# PROPTOTYPE - not yet ready for general release
#
# Make calendars,
#    with a picture at the top
#    public holiday text in boxes as appropriate
#    aniversary text in boxes as appropriate
#    - for my use, added oncall displays
#    - for my use, added when people are on leave
#
# Uses the unix 'cal' output as a basis of the calendar box layout.
#
#      November 2008    
#   Su Mo Tu We Th Fr Sa
#                      1
#    2  3  4  5  6  7  8
#    9 10 11 12 13 14 15
#   16 17 18 19 20 21 22
#   23 24 25 26 27 28 29
#   30
#
#
picfile="picture_list.txt"         #  Year Month Picture-url
holidayfile="public_hols.txt"      #  Year Month Day:Text description
aniversaryfile="aniversaries.txt"  #  Month Day:Text description, no year, these repeat
reminderfile="event_reminders.txt" #  Year Month Day:Text description
oncallfile="opt/oncall_dates.txt"  #  Year Month Day:Person:Colour  
onleavefile="opt/team_leave.txt"   #  Year Month Day:Person        

#   --------------- see what files are available ----------
# Cut down on disk IO. To avoid checkimg if a file is readable
# for every new date being processed check once at the start 
# and use variable tests instead inside the loop when determining
# if the file is available..
if [ -r ${holidayfile} ];
then
   UseHols="yes"
else
   UseHols="no"
fi
if [ -r ${aniversaryfile} ];
then
   UseAniv="yes"
else
   UseAniv="no"
fi
if [ -r ${reminderfile} ];
then
   UseRemind="yes"
else
   UseRemind="no"
fi
if [ -r ${oncallfile} ];
then
   UseCall="yes"
else
   UseCall="no"
fi
if [ -r ${onleavefile} ];
then
   UseLeave="yes"
else
   UseLeave="no"
fi
#   --------------- end of see what files are available ----------

# --------------------------------------------------------------------------------
# split_lines - a kludge workaround
#
# This is a kludge, if using a pipe inside a loop that starts a subshell
# which prevents updates to global variables outside the loop; so a string
# cannot be built from multiple input lines.
# This is a workaround, all the lines are passed and the string is built echoing 
# every addition; the caller needs to 'tail -1' the output of this subroutine
# to obtain for use only the last valid output line.
#
# required as I found some dates could have multiple entries for a date in the
# data files so the script needs to handle those cases.
# --------------------------------------------------------------------------------
split_lines() {
   alllines="$1"
   brlines=""
   echo "${alllines}" | while read oneline
   do
      if [ "${brlines}." == "." ];
      then 
         brlines="${oneline}"
      else
         brlines="${brlines}<br />${oneline}"
      fi
      echo "${brlines}"
   done
} # end of split_lines

# ----------------------------------------------------------------------
# Writes a single box entry.
# A seperate routine to keep all the file greping and line parsing
# from cluttering up the mainline code.
# ----------------------------------------------------------------------
build_one_entry() {
   yr="$1"
   mt="$2"
   dy="$3"

   if [ "${dy}." != "." ];
   then
      entrylinecount=0
      pubholtext=""
      aniversarytext=""
      remindertext=""
      oncalltext=""         # Added for my use
      onleavetext=""        # Added for my use
      # Surely only one public holiday on any given date
      if [ "${UseHols}." == "yes." ];
      then
         ispubhol=`grep "${yr} ${mt} ${dy}:" ${holidayfile}`
         if [ "${ispubhol}." != "." ];
         then
            pubholtext=`echo "${ispubhol}" | awk -F: {'print $2'}`
            pubholtext="<span style=\"color:red\">${pubholtext}</span>"
         fi
      fi
      # Can be more than one aniversary on a given date so back to kludging
      if [ "${UseAniv}." == "yes." ];
      then
         datalines=`grep "${mt} ${dy}:" ${aniversaryfile} | awk -F: {'print $2'}`
         aniversarytext=`split_lines "${datalines}" | tail -1`
         aniversarytext="<span style=\"color:green\">${aniversarytext}</span>"
      fi
      # Do this expecting multiple entries, may be more than one
      # reminder for any given date.
      # Because of the pipe which starts a subshell the global variable
      # is not updated. So have to do it this messy way and use the last line produced
      if [ "${UseRemind}." == "yes." ];
      then
         datalines=`grep "${yr} ${mt} ${dy}:" ${reminderfile} | awk -F: {'print $2'}`
         remindertext=`split_lines "${datalines}" | tail -1`
         remindertext="<span style=\"color:blue\">${remindertext}</span>"
      fi
      # only one oncall entry per date expected (and only one handled)
      if [ "${UseCall}." == "yes." ];
      then
         isoncall=`grep "${yr} ${mt} ${dy}:" ${oncallfile}`
         if [ "${isoncall}." != "." ];
         then
            oncalltext=`echo "${isoncall}" | awk -F: {'print $2'}`
            oncallcolour=`echo "${isoncall}" | awk -F: {'print $3'}`
            oncalltext="${oncalltext} oncall"
            oncalltext="<span style=\"background-color:${oncallcolour}\">${oncalltext}</span>"
         fi
      fi
      if [ "${UseLeave}." == "yes." ];
      then
         isonleave=`grep "${yr} ${mt} ${dy}:" ${onleavefile}`
         if [ "${isonleave}." != "." ];
         then
            onleavename=`echo "${isonleave}" | awk -F: {'print $2'}`
            onleavetext="<span style=\"background-color:pink\">${onleavename} on leave</span>"
         fi
      fi
      # what data do we have to display ?
      dataoutline="<b><big>${dy}</big></b>"
      if [ "${pubholtext}." != "." ];
      then
         dataoutline="${dataoutline}<br \>${pubholtext}"
         entrylinecount=$(( ${entrylinecount} + 1 ))
      fi
      if [ "${remindertext}." != "." ];
      then
         dataoutline="${dataoutline}<br \>${remindertext}"
         entrylinecount=$(( ${entrylinecount} + 1 ))
      fi
      if [ "${aniversarytext}." != "." ];
      then
         dataoutline="${dataoutline}<br \>${aniversarytext}"
         entrylinecount=$(( ${entrylinecount} + 1 ))
      fi
      if [ "${oncalltext}." != "." ];
      then
         dataoutline="${dataoutline}<br \>${oncalltext}"
         entrylinecount=$(( ${entrylinecount} + 1 ))
      fi
      if [ "${onleavetext}." != "." ];
      then
         dataoutline="${dataoutline}<br \>${onleavetext}"
         entrylinecount=$(( ${entrylinecount} + 1 ))
      fi
      # We have everything to output now, want a minimum of 5 lines in each table line
      echo "<td>${dataoutline}"
      while [ ${entrylinecount} -lt 5 ];
      do
         echo -n "<br />"
         entrylinecount=$(( ${entrylinecount} + 1 ))
      done
      echo "</td>"
   # no else, loop that calls us could at end of month request a blank line we do not want
   fi
} # build_one_entry


# ----------------------------------------------------------------------
# do_one_month
# Produces one month of the calendar.
# Basically does a 'cal' for the year and month, throws up the
# picture for the month, the header (mmmm yyyy), and starts the
# table we are using.
# When its finished processing the 'cal' output closes the table.
# ----------------------------------------------------------------------
do_one_month() {
   usemonth="$1"
   useyear="$2"
   echo "<center>"
   lineno=1
   # C R A P --- C R A P --- C R A P
   # read drops off the leading spaces in cal | while read dataline
   # also if using a file for cal output.
   cal ${usemonth} ${useyear} | while read dataline 
   do
      # Only on line one do we pull out the month header, find the
      # picture, and write the picture and banner.
      if [ "${lineno}." == "1." ];
      then
         month=`echo "${dataline}" | awk {'print $1'}`
         year=`echo "${dataline}" | awk {'print $2'}`
         monthpic=`grep "${year} ${month}" ${picfile} | awk {'print $3'}`
         # if user has not kept the picture file up-to-date if there is no
         # picture for an exact "year month" try and locate one for any "yyyy month"
         if [ "${monthpic}." == "." ];
         then
            monthpic=`grep ".... ${month}" ${picfile} | awk {'print $3'}`
         fi
         # only show the picture if we have one
         if [ "${monthpic}." != "." ];
         then
            echo "<img src=\"${monthpic}\" height=\"800px\"></img>"
         else
            echo "<p>No picture provided for ${year}/${month}.</p>"
         fi
         echo "<br /><h1>${dataline}</h1>"
         echo "<br /><br /><br />"       # some spaces to align the page better
      fi
      # Only on line 2 do we start the table and populate the first line
      # of the table with the day names
      if [ "${lineno}." == "2." ];
      then
          cat << EOF
<table border="1" width="90%">
<tr><td>Sunday   </td><td>Monday   </td><td>Tuesday  </td><td>Wednesday</td>
<td>Thursday </td><td>Friday   </td><td>Saturday </td></tr>
EOF
      fi
      # Anything else is the day numbers to populate the table with.
      # This is where we also need to parse the public holiday and
      # aniversary file tables.
      if [ ${lineno} -gt 2 ];
      then
          # CRUD fix.
          # We know we want the line length to have space leaders to give
          # us a full line, so add back in the leading spaces we need now.
          neededlen=20
          linelen=${#dataline}
          position1=${dataline:0:2}         # oopsy, don't space full the last line
          if [ "${position1}." == "." ];
          then
             position1="11"    #HMM, what was I doing here, stop it for now with a gt 10
          fi
          if [ ${position1} -lt 10 ];       # only space fill if number was low enough
          then                              # to have has the spaces stripped out.
             while [ ${#dataline} -lt ${neededlen} ];
             do
                dataline=" ${dataline}"
             done
          fi
          # then back to business as usual
          position1=${dataline:0:2}
          position2=${dataline:3:2}
          position3=${dataline:6:2}
          position4=${dataline:9:2}
          position5=${dataline:12:2}
          position6=${dataline:15:2}
          position7=${dataline:18:2}
          echo "<tr>"
          build_one_entry "${year}" "${month}" "${position1}"
          build_one_entry "${year}" "${month}" "${position2}"
          build_one_entry "${year}" "${month}" "${position3}"
          build_one_entry "${year}" "${month}" "${position4}"
          build_one_entry "${year}" "${month}" "${position5}"
          build_one_entry "${year}" "${month}" "${position6}"
          build_one_entry "${year}" "${month}" "${position7}"
          echo "</tr>"
      fi
      lineno=$((${lineno} + 1))
   done

   # Close the table
   echo "</table>"
   echo "</center>"

   # Add a page break to be used when printing
   echo "<div class=\"page-break\"></div>"
} # do_one_month


cat << EOF
Content-Type: text/html


<HTML>
<HEAD><TITLE>Calendar Creator</TITLE>

<style type="text/css">
@media all
{
  .page-break   { display:none; }
}
@media print {
  body{
    -webkit-print-color-adjust: exact; /*chrome & webkit browsers*/
    print-color-adjust: exact; /*firefox & IE */
  } 
  .page-break   { display:block; page-break-before:always; }
}
</style>

</HEAD>
<BODY>
EOF

errors="no"
if [ ! -f ${picfile} ];
then
   errors="yes"
   echo "<b>*error*</b> no picture file found, ${picfile}<br />"
fi
if [ ! -f ${holidayfile} ];
then
   errors="yes"
   echo "<b>*error*</b> no holiday file found, ${holidayfile}<br />"
fi
if [ "${errors}." == "no." ];
then
   # loop for the next 12 months starting in the current month
   currmonthnow=`date +"%m"`   # if 0n remove leading 0 or it is treated as octal
   if [ "${currmonthnow:0:1}." == "0." ];
   then
      currmonthnow=${currmonthnow:1:1}
   fi
   workmonthnow=${currmonthnow}           # used as first loop counter up to 12
   workyearnow=`date +"%Y"`               # cunnent year, as var as we bump when above 12
   while [ ${workmonthnow} -lt 13 ];
   do
      do_one_month ${workmonthnow} ${workyearnow}
      workmonthnow=$(( ${workmonthnow} + 1 ))
   done
   workmonthnow=1                                  # next year from month 1
   workyearnow=$(( ${workyearnow} + 1 ))           # in the next year
   while [ ${workmonthnow} -lt ${currmonthnow} ];  # until we reach start month
   do
      do_one_month ${workmonthnow} ${workyearnow}
      workmonthnow=$(( ${workmonthnow} + 1 ))
   done
fi

# Close the web page
echo "</BODY></HTML>"
exit 0
