===============================================================================
Start of README.txt for optional files
===============================================================================

These are all optional files added for my own use.
If these files exist in the "opt" directory under the main calendar directory
that the calendar.sh file lives in they will be used; if the files do not exist
then a calendar will be produced as per the README.txt in the main directory.

They have been aded for functions I need to keep track of my life; or at
least keep track of where a work life will impact my life.

-------------------------------------------------------------------------------
team_leave.txt   (OPTIONAL - added for my use, you probably do not want this)
^^^^^^^^^^^^^^
Added for my use. Helps me visualise when people are scheduled to be on leave.
Examples...
2025 March  5:mark
2025 March 16:mark
2025 April  7:mark
2025 September  9:fred
2025 September 10:fred

oncall_dates.txt   (OPTIONAL - added for my use, you probably do not want this)
^^^^^^^^^^^^^^^^
This was added as a new addition for my use to track when I am oncall.
It is entirely optional (you are unlikely to need it) and if it does not
exist script processing is much faster.
It requires exact dates, who is oncall, and a background colour to be used for
the text (the text used is the name of who is oncall). I use seperate colours
here so I can easily see when I am oncall.

The syntax of each line is "year fullmonth dayofmonth:person:background-colour"
Examples...
2025 March  5:mark:lightgreen
2025 March  6:mark:lightgreen
2025 March  7:mark:lightgreen
2025 March  8:mark:lightgreen
2025 March  9:mark:lightgreen
2025 March 10:fred:lightblue
2025 March 11:fred:lightblue
2025 March 12:fred:lightblue
2025 March 13:fred:lightblue

generate_oncall.sh
^^^^^^^^^^^^^^^^^^
As it is unreasonable to manually type in a years worth of dates for
the oncall file you should refer to the "generate_oncall.sh" script
which will make this easier.
You will need to edit it for your use. As it stands it is set for
- monday is changeover day
- two people oncall
- 14 day oncall intervals
- start date for the first person in the oncall list hard coded (you edit that)
- date generation stops at the end of 2025 (you can edit that)
So you can use this script to populate a file with a full years of dates for 
default intervals; and just edit that list for exceptions on individual dates
such as someone taking holidays.

===============================================================================
End of README.txt for optional files
===============================================================================
