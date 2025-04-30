#!/bin/bash
#
# Quick and dirty script to generate oncall roster dates for use by my calendar
# script.
# In my team only two oncall, 14 day rotation.
#
startdate="24Feb2025 13:00"   # where to start generating, start of a oncall period
                             # Use a time in the above, if defaulting to 00:00 DST changes make duplicate entries
interval_days="14"        # oncall period
last_year_to_generate="2025"    # do not loop beyond Dec of this year

# A colour for each persons oncall, or no variable for a user if no colour to be used
# Can be used to create individual calendars with only one persons
# oncall highlighted this way so individual user calendars could be
# created that are more readable
# TODO, make it a parameter list to make it easier ?
colour_luke="lightblue"
colour_mark="lightgreen"

work_date=`date --date="${startdate}" +"%s"`    # seconds since EPOC
work_year=`date --date="@${work_date}" +"%Y"`   # year at current calculation
while [ ${work_year} -le ${last_year_to_generate} ];
do
   # Mark
   work_interval_count="${interval_days}"
   while [ ${work_interval_count} -gt 0 ];
   do
      display_date=`date --date="@${work_date}" +"%Y %B %_d"`
      echo "${display_date}:mark:${colour_mark}"
      work_interval_count=$((${work_interval_count} - 1))   # decrement so loop eventually stops
      work_date=$(( ${work_date} + (60 * 60 * 24) ))   # plus 1 days seconds
   done
   # Luke
   work_interval_count="${interval_days}"
   while [ ${work_interval_count} -gt 0 ];
   do
      display_date=`date --date="@${work_date}" +"%Y %B %_d"`
      echo "${display_date}:luke:${colour_luke}"
      work_interval_count=$((${work_interval_count} - 1))   # decrement so loop eventually stops
      work_date=$(( ${work_date} + (60 * 60 * 24) ))   # plus 1 days seconds
   done
   work_year=`date --date="@${work_date}" +"%Y"`   # year at current calculation point to stop loop
done

exit 0
