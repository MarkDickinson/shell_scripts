#!/bin/bash
#
# resize_and_merge_videos.sh
#
# Always difficult to merge video files with different resolutions.
# This script will use ffmpeg to resize and merge video files as 1280:720.
#
# WARNING: ONLY USE WITH MKV FILES (see notes at the end on why not to
#          use MP4 files with this script).
#
# It builds the ffmpeg command to use in a command file which
# will be executed and removed when done, or you can pass a
# flag to limit it to conly creating the command file to
# review (ie: when debugging) before running manually.
# Input files are expected to have both video and audio streams.
#
# Disclaimers
#  - Only tested against a directory containing max 17 MKV files; that worked fine.
#  - And failed testing with MP4 so DO NOT USE MP4 files (see notes at end).
#
# If cpulimit is installed it will try to use that to throttle
# ffmpeg which by default will use 100% of all your CPUs which
# you don't want when trying to use the desktop for other things
# at the same time (unless you want to stress test your cpu fan(s)).
#
# ======== Script command syntax =========
# syntax: resize_and_merge_videos.sh mkv|mp4 [anything]
# parms explained:
#   - suffix of input files must be mkv or mp4 (lowercase)
#     and no mixing of file types permitted
#     IMPORTANT: mp4 no longer supported, until I work out why it does not work
#   - if any text is provided as an extra parm the 'tmpcmd'
#     workfile is created but not executed or deleted so can 
#     be reviewed before running it manually
#

file_suffix="$1"
only_create_workfile="$2"

if [ "${file_suffix}." != "mkv." -a "${file_suffix}." != "mp4." ];
then
   echo "REQUIRE an input file type of mkv or mp4"
   exit 1
fi

# only allow mkv for now, see notes at the end for why
if [ "${file_suffix}." != "mkv." ];
then
   echo "Only mkv supported at present, known issues with mp4"
   exit 1
fi

have_ffmpeg=`which ffmpeg`
if [ "${have_ffmpeg}." == "." ];
then
   echo "ffmpeg is not in your search path, is the package installed ?"
   exit 1
fi

# Build the command string into this file
workfile="tmpcmd"

numfiles=`ls *${file_suffix} | wc -l`
have_cpulimit=`which cpulimit`
if [ "${have_cpulimit}." != "." ]
then
   # Different versions of cpulimit installed on Debian, rhel and some old servers
   # phoenix is my main desktop with an old version so cater for that syntax difference
   # almost all others are debian so thats the default cmd if server is not phoenix.
   # NOTE: -m and -i are OK for ffmpeg, never use for scripts that spawn lots of subtasks !
   myhost=`hostname | awk -F. {'print $1'}`  # strip off the domain part if present
   if [ "${myhost}." == "phoenix." ];  # has an old version of cpulimit with different syntax
   then
      cpulimitcmd="cpulimit -i -l80"
   else                                # else the standard debian one
      cpulimitcmd="cpulimit -m -l80 --"
   fi
   echo "${cpulimitcmd} ffmpeg \\" > ${workfile}
else
   echo "***** CPULIMIT NOT INSTALLED, WIL USE 100% OF ALL CPUS *****"
   echo 'ffmpeg \' > ${workfile}
fi
ls *${file_suffix} | while read fname
do
   echo "-i \"${fname}\" \\" >> ${workfile}
done
echo '-filter_complex \' >> ${workfile}
loopcount=0
echo '" \' >> ${workfile}
while [ ${loopcount} -lt ${numfiles} ];
do
   echo "[${loopcount}:v]scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2[v${loopcount}]; \\" >> ${workfile}
   loopcount=$(( ${loopcount} + 1 ))
done

loopcount=0
while [ ${loopcount} -lt ${numfiles} ];
do
   echo -n "[v${loopcount}][${loopcount}:a]" >> ${workfile}
   loopcount=$(( ${loopcount} + 1 ))
done
echo "concat=n=${numfiles}:v=1:a=1[v][a]\" \\" >> ${workfile}
echo '-map "[v]" -map "[a]" -c:v libx264 -c:a aac \' >> ${workfile}
echo "merged_output.${file_suffix}" >> ${workfile}

# And run the command, and clean up the workfile
if [ -f "${workfile}" ];
then
   if [ "${only_create_workfile}." == "." ];
   then
      bash "${workfile}"
      /bin/rm ${workfile}
      echo "--> Merged output file is merged_output.${file_suffix}"
      ls -la merged_output.${file_suffix}
      # So I do not to have to pay attention and can be told when completed
      have_espeak=`which espeak`
      if [ "${have_espeak}." != "." ];
      then
         echo "video resize and merge has completed" | espeak --stdin
         sleep 1
         echo "check the merged output file" | espeak --stdin
      else
         echo "If you install espeak I can verbally tell you when it completes"
      fi
   else
      echo "--> Command file created as ${workfile}"
      echo "Review and if happy run it with 'bash ${workfile}'"
   fi
fi
# All done
exit 0
# =================== Testing Notes ========================
#
# Trying to merge MP4 files was a miserable failure.
# Trying to merge MKV files is a 100% success.
#
# If I get bored I may look at why MP4 fails so miserably, but
# at only takes a few secs to read/save them as MKV with avidemux
# so I may never get around to investigating that. 
# I do not need to do this often, and only wrote a script because
# I could not be bothered resizing and then merging 17 files one
# at a time with a combination of tools; I may never need this again.
#
# ------------ notes on MP4 - DO NOT USE MP4 -----------
#-rw-r--r--. 1 mark mark  92786957 Oct 10 10:43 file1.mp4
#-rw-r--r--. 1 mark mark  36465774 Oct 10 11:25 file2.mp4
#-rw-r--r--. 1 mark mark  28098659 Oct 10 11:28 file3.mp4
#-rw-r--r--. 1 mark mark 121261905 Oct 10 11:33 file4.mp4
#-rw-r--r--. 1 mark mark  33281160 Oct 10 11:41 file5.mp4
#-rw-r--r--. 1 mark mark 575930416 Oct 11 09:30 merged_output.mp4 (BAD, 1sec duration, ^C out)
#
#MP4 after 18 hours NOT COMPLETED (I ctrl ^C out),
# only 1 sec saved from mp4 input, over 100,000 duplicate frames dropped
#frame=1150000 fps= 15 q=33.0 size=  545792kB time=00:00:01.20 bitrate=3702988.0kbits/s dup=1149930
#frame=1183333 fps= 16 q=33.0 size=  559104kB time=00:00:01.20 bitrate=3793304.8kbits/s dup=1183261
#frame=1183333 fps= 15 q=33.0 size=  559104kB time=00:00:01.23 bitrate=3721732.9kbits/s dup=1183261
#
# ------------ notes on MKV - DO USE MKV -----------
#
# Used avidemux to open/save the above mp4 files as mkv [aa1-aa5], no changes
# made to any of the files other than just saving them as mkv; avidemux did
# not warn of any timestamp issues and after saving ffprobe still reported
# the saved mkv files as still using different resolutions as expected.
#
# MKV completed after 20mins, zero frames dropped, and the correct duration
# frame=46830 fps= 39 q=-1.0 Lsize=  296857kB time=00:22:51.23 bitrate=1773.5kbits/s speed=1.14x
#
#-rw-r--r--. 1 mark mark  92786957 Oct 10 10:43 file1.mp4
#-rw-r--r--. 1 mark mark  36465774 Oct 10 11:25 file2.mp4
#-rw-r--r--. 1 mark mark  28098659 Oct 10 11:28 file3.mp4
#-rw-r--r--. 1 mark mark 121261905 Oct 10 11:33 file4.mp4
#-rw-r--r--. 1 mark mark  33281160 Oct 10 11:41 file5.mp4
#-rw-r--r--. 1 mark mark  92658644 Oct 11 09:33 aa1.mkv
#-rw-r--r--. 1 mark mark  36384010 Oct 11 09:34 aa2.mkv
#-rw-r--r--. 1 mark mark  28015776 Oct 11 09:34 aa3.mkv
#-rw-r--r--. 1 mark mark 116035944 Oct 11 09:35 aa4.mkv
#-rw-r--r--. 1 mark mark  31790609 Oct 11 09:36 aa5.mkv
#-rw-r--r--. 1 mark mark       877 Oct 11 09:42 docnotes.txt
#-rw-r--r--. 1 mark mark 303981865 Oct 11 10:00 merged_output.mkv (GOOD)
#
# =================== End Notes ========================
