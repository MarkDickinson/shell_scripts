===============================================================================
Start of README.txt
===============================================================================

Name: My calendar generation script "calendar.sh"
      (needs a web server; 
       or could be run on a desktop Linux server [see usage note1])

      Could be considered BETA; a lot of bad scripting to get to
      the results I wanted with minimal effort; may be useful to others.

Function:
    Use a webserver CGI script to produce a calendar
    - different pictures for each month    (file picture_list.txt)
    - populate with aniversary/birthdays   (file aniversaries.txt)
    - populate with public holidays        (file public_hols.txt)

History:
    Basically I did not want a overly expensive commercial calendar generator,
    and did not want my pictures uploaded to internet based calendar sites to
    use those.
    And it is simple to do using generated html (it requires only "bash" and "cal").
    Designed to run on my home webserver as a CGI script but should work perfectly
    well on a Linux desktop (see usage note1).

Usage: -- repeat every year :-)
    1. Install on your own web server in a directory under your cgi-bin
    2. Edit the pictres.txt and aniversaries.txt to define your own 
       pictures and aniversaries/birtdays to be put into the calendar
       (format of entries in those files discussed below)
    3. point a web-browser at your-webserver/cgi-bin/your-install-dir/calendar.sh
    4. in the browser select file, print. For windows users I would recomend
       printing to the inbuilt "print to pdf" function; otherwise directly to 
       a printer
    note1: if you do not have a web server but do have a linux desktop you
           could just run the script as "calendar.sh > some-outputfile.html" 
           and use your desktop web browser to "open file" to view/print the results,
           BUT the picture_list.txt file will need to refer to pictures relative
           to the directory you direct the output file to (instead of paths your
           webserver would use) for the picture URL path.
           Must be a Linux server, it needs the "cal" program; and some bash builtins.
    note2: yes the picture list is URLs... http[s]://somesite/somepic.jpg could be
           used BUT do not use other peoples pictures; thats simply bad manners.

Important things to be aware of:
    In data files day numbers if < 10 must be preceeded by a space, not a zero
    and not with the space omitted alltogether
    (ie: "March  9" is valid, "March 9" or "March 09" will be ignored).

The main file : calendar.sh
    This is the CGI script your webserver will run to produce the calendar page.
    The data files are expected to be in the same directory as the script.
    It is dependant on having the unix "cal" program installed, because I use
    that to work out what a month looks like instead of reinventing the wheel.
    IMPORTANT: it will generate a calendar for 12 months from/including the
               current month, that is not customisable yet.

===============================================================================
Data files used: READ THIS SECTION
-------------------------------------------------------------------------------
aniversaries.txt
^^^^^^^^^^^^^^^^
This file is used for things that always occur on the same date every year,
so there is no YEAR value in the data field key. This would be things like
birthdays and anniversaries that always occur on the same date.
The syntax of each line is "fullmonth dayofmonth:text to display"
If dayofmonth is < 10 remember to have a leading space not a leading zero.
Examples...
January 16:Nics Birthday
February  8:Marks Birthday
December  5:Jessica,Panther,Tigers<br />birthdays observed

-------------------------------------------------------------------------------
picture_list.txt
^^^^^^^^^^^^^^^^
This file is used to define the picture to be used for each month of
the calendar. It is IMPORTANT to note that these are URL references
to the picture location on your webserver not directory paths...
remember this script is run by your webserver.
(except for note1 in usage earlier, you may want to use filesystem
path references rather than webserver urls).

As a calendar for multiple years can be produced a YEAR value is reqd.
NOTE: you can predefine a few years, perfectly acceptable to have
      entries in this file that are not needed in processing
IMPORTANT: you should have unique pictures for "year month" but to cater
           for cases where you forget to update the picture_list.txt file
           if it is unable to find an exact match it will search for a
           picture for the month from any year; if that also cannot be
           found it will display text that there is no picture.

The syntax of each line is "year fullmonth url-of-picture"
Examples for 12 months...
2025 April /personal_space/pics/sam/sam_asleep_3_optimized.jpg
2025 May /personal_space/pics/snowy/snowy_02_optimized.jpg
2025 June /personal_space/pics/sam/sam_asleep_1_optimized.jpg
2025 July ./localdirref/some-local-picture.jpg
2025 August ./localdirref/some-local-picture2.jpg
2025 September /personal_space/pics/snowy/snowy_01_optimized.jpg
2025 October /personal_space/pics/3cats/3Cats_001.jpg
2025 November http://somewebsite/do-not-steal-other-peoples-pictures.jpg
2025 December /personal_space/pics/3cats/3Cats_003.jpg
2026 January /personal_space/pics/fletcher/fletcher_3_optimized.jpg
2026 February /personal_space/pics/sam/sam_playing.jpg
2026 March /personal_space/pics/fletcher/fletcher_1_optimized.jpg

-------------------------------------------------------------------------------
public_hols.txt
^^^^^^^^^^^^^^^
This file is used to define the public holidays for your location.
As these can change year to year the full date is required.
The syntax of each line is "year fullmonth dayofmonth:text to display"
If dayofmonth is < 10 remember to have a leading space not a leading zero.
Examples (NZ)...
2025 January  1:New Years Day
2025 January  2:Day after new years
2025 February  6:Waitangi Day
2025 April 18:Good Friday
2025 April 21:Easter Monday
2025 April 25:Anzac Day
2025 June  2:NZ Kings<br />Birthday 
2025 June  9:AUZ Kings<br />Birthday
2025 June 20:NZ Matariki
2025 October 27:NZ Labour Day
2025 December 25:Christmas Day
2025 December 26:Boxing Day 
2026 January  1:New Years Day
2026 January  2:Day after new years
2026 February  6:Waitangi Day
2026 April 3:Good Friday
2026 April 6:Easter Monday
2026 April 27:Anzac Day observed
2026 June  1:Kings<br />Birthday
2026 July 10:Matariki
2026 October 26:Labour Day
2026 December 25:Christmas Day
2026 December 28:Boxing Day observed

-------------------------------------------------------------------------------
Optional files you are unlikely to ever need are documented in the "opt"
directory under this one.

===============================================================================
End of README.txt
===============================================================================
