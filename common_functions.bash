# =========================================================================
# Library that can be sourced into bash scripts.
#
# These are routines that are common across many of my scripts,
# in a script 'source common_functions.bash' or '. ./common_functions.bash'
# then call as documented from within your scripts.
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
# T O D O - additional tests that may be more useful
#   If readlink is installed (on most linux servers) you can also
#   use the below to obtain the device being used for stdin (0) and stdout (1)
#   which may be of more use to me in scripts that redirect input and output
#   Should test for pts and whatever xterm uses to decide if a terminal or batch.
#      $ readlink /proc/self/fd/0
#      /dev/pts/0
#      $ readlink /proc/self/fd/1
#      /dev/pts/0
#   readlink is just a note for now, I will probably need it
#   also depending on where you use it you could get "pipe:[nnnnnn]"
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

# *********************************************************************
#
# text_icon:   bash routine
#
# Return the character/icon requested that can
# be added or inserted to a text string.
# Because I am too lazy to remember character codes.
#
# CAUTION: This is too large to be used regularly,
#          you should edit and delete the icon characters
#          you are unlikely to use. It will work better 
#          with 100 or so common ones you use, as stored
#          here it has over 1000 in the case statement
#          (most of those defined at w3schools)
#
# example:
#    aa=`text_icon robot`
#    echo "Robot icon ${aa} inserted"
#  or more simply inline (with double quote not single quote)
#    echo "Robot icon `text_icon robot` inserted"
#  or inline with selection changed by variable
#    useval="robot"
#    echo "Robot icon `text_icon ${useval}` inserted"
#
# *********************************************************************
text_icon() {
   iconname="$1"

   # if the terminal is not UTF-8 then it probably cannot
   # display the characters so do not bother.
   supported=`locale charmap`
   if [ "${supported}." != "UTF-8." ];
   then
      echo -n ""
      exit
   fi

   # and check if the request matches what we have as available
   case "${iconname}" in
      "abacus") echo -n "🧮" ;;
      "adult") echo -n "🧑" ;;
      "aerial_tramway") echo -n "🚡" ;;
      "alien_monster") echo -n "👾" ;;
      "ambulance") echo -n "🚑" ;;
      "american_football") echo -n "🏈" ;;
      "amphora") echo -n "🏺" ;;
      "anger") echo -n "💢" ;;
      "angry_face") echo -n "😠" ;;
      "anguished_face") echo -n "😧" ;;
      "ant") echo -n "🐜" ;;
      "antenna_bars") echo -n "📶" ;;
      "anticlockwise_circle_arrows") echo -n "🔄" ;;
      "articulated_lorry") echo -n "🚛" ;;
      "artist_palette") echo -n "🎨" ;;
      "ascending_notes") echo -n "🎜" ;;
      "astonished_face") echo -n "😲" ;;
      "athletic_shoe") echo -n "👟" ;;
      "atm_bank") echo -n "🏧" ;;
      "aubergine") echo -n "🍆" ;;
      "automobile") echo -n "🚗" ;;
      "auto_rickshaw") echo -n "🛺" ;;
      "avocado") echo -n "🥑" ;;
      "babminton") echo -n "🏸" ;;
      "baby_angel") echo -n "👼" ;;
      "baby_bottle") echo -n "🍼" ;;
      "baby_chick") echo -n "🐤" ;;
      "baby") echo -n "👶" ;;
      "baby2") echo -n "🚼" ;;
      "back_with_arrow") echo -n "🔙" ;;
      "bacon") echo -n "🥓" ;;
      "badger") echo -n "🦡" ;;
      "bagel") echo -n "🥯" ;;
      "baggage_claim") echo -n "🛄" ;;
      "baguette") echo -n "🥖" ;;
      "bald") echo -n "🦲" ;;
      "ballet_shoes") echo -n "🩰" ;;
      "ball_of_yarn") echo -n "🧶" ;;
      "ballon") echo -n "🎈" ;;
      "banana") echo -n "🍌" ;;
      "bank") echo -n "🏦" ;;
      "banknote_dollar") echo -n "💵" ;;
      "banknote_euro") echo -n "💶" ;;
      "banknote_pound") echo -n "💷" ;;
      "banknote_yen") echo -n "💴" ;;
      "barber_pole") echo -n "💈" ;;
      "bar_chart") echo -n "📊" ;;
      "baseball") echo -n "⚾" ;;
      "basketball") echo -n "🏀" ;;
      "basket") echo -n "🧺" ;;
      "bat") echo -n "🦇" ;;
      "bath") echo -n "🛀" ;;
      "bathtub") echo -n "🛁" ;;
      "battery") echo -n "🔋" ;;
      "beach_with_umbrella") echo -n "🏖" ;;
      "bearded_man") echo -n "🧔" ;;
      "bear_face") echo -n "🐻" ;;
      "beating_heart") echo -n "💓" ;;
      "beaver") echo -n "🦫" ;;
      "bed") echo -n "🛏" ;;
      "beer_mug") echo -n "🍺" ;;
      "beer_mugs") echo -n "🍻" ;;
      "bell") echo -n "🔔" ;;
      "bellhop_bell") echo -n "🛎" ;;
      "bento_box") echo -n "🍱" ;;
      "beverage_box") echo -n "🧃" ;;
      "bicycle") echo -n "🚲" ;;
      "bicyclist") echo -n "🚴" ;;
      "bikini") echo -n "👙" ;;
      "billed_cap") echo -n "🧢" ;;
      "billiards") echo -n "🎱" ;;
      "bird") echo -n "🐦" ;;
      "birthday_cake") echo -n "🎂" ;;
      "bison") echo -n "🦬" ;;
      "black_ballpoint_pen") echo -n "🖊" ;;
      "black_circle") echo -n "⏺" ;;
      "black_droplet") echo -n "🌤" ;;
      "black_flag") echo -n "🏴" ;;
      "black_heart") echo -n "🖤" ;;
      "black_latin_cross") echo -n "🕇" ;;
      "black_pennant") echo -n "🏲" ;;
      "black_pushpin") echo -n "🖈" ;;
      "black_rosette") echo -n "🏶" ;;
      "black_skull_and_bones") echo -n "🕱" ;;
      "black_square_button") echo -n "🔲" ;;
      "black_square") echo -n "⏹" ;;
      "black_touch_telephone") echo -n "🕿" ;;
      "blood_drop") echo -n "🩸" ;;
      "blossom") echo -n "🌼" ;;
      "blowfish") echo -n "🐡" ;;
      "blue_book") echo -n "📘" ;;
      "blue_heart") echo -n "💙" ;;
      "boar") echo -n "🐗" ;;
      "bomb") echo -n "💣" ;;
      "bone") echo -n "🦴" ;;
      "book") echo -n "🕮" ;;
      "bookmark") echo -n "🔖" ;;
      "bookmark_tabs") echo -n "📑" ;;
      "books") echo -n "📚" ;;
      "boomerang") echo -n "🪃" ;;
      "bouquet") echo -n "💐" ;;
      "bow_and_arrow") echo -n "🏹" ;;
      "bowing_deeply") echo -n "🙇" ;;
      "bowling") echo -n "🎳" ;;
      "bowl_with_spoon") echo -n "🥣" ;;
      "boxing") echo -n "🥊" ;;
      "boy") echo -n "👦" ;;
      "boys") echo -n "🛉" ;;
      "brain") echo -n "🧠" ;;
      "bread") echo -n "🍞" ;;
      "breast_feeding") echo -n "🤱" ;;
      "bricks") echo -n "🧱" ;;
      "bride") echo -n "👰" ;;
      "bridge_at_night") echo -n "🌉" ;;
      "briefcase") echo -n "💼" ;;
      "briefs") echo -n "🩲" ;;
      "broccoli") echo -n "🥦" ;;
      "broken_heart") echo -n "💔" ;;
      "broom") echo -n "🧹" ;;
      "brown_heart") echo -n "🤎" ;;
      "bug") echo -n "🐛" ;;
      "building_construction") echo -n "🏗" ;;
      "buisness_suit") echo -n "🕴" ;;
      "bullhorn") echo -n "🕫" ;;
      "bullhorn_with_waves") echo -n "🕬" ;;
      "bunnies") echo -n "👯" ;;
      "burrito") echo -n "🌯" ;;
      "bus") echo -n "🚌" ;;
      "bus_small") echo -n "🛺" ;;
      "bus_stop") echo -n "🚏" ;;
      "bust") echo -n "👤" ;;
      "busts") echo -n "👥" ;;
      "butter") echo -n "🧈" ;;
      "butterfly") echo -n "🦋" ;;
      "cactus") echo -n "🌵" ;;
      "calendar") echo -n "📅" ;;
      "camel") echo -n "🐫" ;;
      "camera") echo -n "📷" ;;
      "camera_with_flash") echo -n "📸" ;;
      "camping") echo -n "🏕" ;;
      "candle") echo -n "🕯" ;;
      "candy") echo -n "🍬" ;;
      "canned_food") echo -n "🥫" ;;
      "canoe") echo -n "🛶" ;;
      "card_index") echo -n "📇" ;;
      "carousel") echo -n "🎠" ;;
      "carp_steamer") echo -n "🎏" ;;
      "carrot") echo -n "🥕" ;;
      "car_small") echo -n "🛻" ;;
      "cartwheel") echo -n "🤸" ;;
      "castle") echo -n "🏰" ;;
      "cat") echo -n "🐈" ;;
      "cat_face") echo -n "🐱" ;;
      "celebration") echo -n "🙌" ;;
      "celtic_cross") echo -n "🕈" ;;
      "cheery_blossom") echo -n "🌸" ;;
      "cheese") echo -n "🧀" ;;
      "chequed_flag") echo -n "🏁" ;;
      "cherries") echo -n "🍒" ;;
      "chestnut") echo -n "🌰" ;;
      "chicken") echo -n "🐔" ;;
      "child") echo -n "🧒" ;;
      "children_crossing") echo -n "🚸" ;;
      "chipmunk") echo -n "🐿" ;;
      "chocolate") echo -n "🍫" ;;
      "chopsticks") echo -n "🥢" ;;
      "christmas_tree") echo -n "🎄" ;;
      "church") echo -n "⛪" ;;
      "cinema") echo -n "🎦" ;;
      "circled_cross_pomme") echo -n "🕀" ;;
      "circus") echo -n "🎪" ;;
      "city1") echo -n "🌆" ;;
      "city2") echo -n "🏙️" ;;
      "cityscape_at_dusk") echo -n "🌆" ;;
      "cityscape") echo -n "🏙" ;;
      "clamshell_mobile_phone") echo -n "🖁" ;;
      "clapper_board") echo -n "🎬" ;;
      "classic_building") echo -n "🏛" ;;
      "climbing") echo -n "🧗" ;;
      "clinking_glass") echo -n "🥂" ;;
      "clipboard") echo -n "📋" ;;
      "clock_1030") echo -n "🕥" ;;
      "clock_10") echo -n "🕙" ;;
      "clock_1130") echo -n "🕦" ;;
      "clock_11") echo -n "🕚" ;;
      "clock_1230") echo -n "🕧" ;;
      "clock_12") echo -n "🕛" ;;
      "clock_130") echo -n "🕜" ;;
      "clock_1") echo -n "🕐" ;;
      "clock_230") echo -n "🕝" ;;
      "clock_2") echo -n "🕑" ;;
      "clock_330") echo -n "🕞" ;;
      "clock_3") echo -n "🕒" ;;
      "clock_430") echo -n "🕟" ;;
      "clock_4") echo -n "🕓" ;;
      "clock_530") echo -n "🕠" ;;
      "clock_5") echo -n "🕔" ;;
      "clock_630") echo -n "🕡" ;;
      "clock_6") echo -n "🕕" ;;
      "clock_730") echo -n "🕢" ;;
      "clock_7") echo -n "🕖" ;;
      "clock_830") echo -n "🕣" ;;
      "clock_8") echo -n "🕗" ;;
      "clock_930") echo -n "🕤" ;;
      "clock_9") echo -n "🕘" ;;
      "clockwise_circle_arrows") echo -n "🔁" ;;
      "clockwise_up_and_down_arrows") echo -n "🔃" ;;
      "closed_book") echo -n "📕" ;;
      "closed_mailbox_low_flag") echo -n "📪" ;;
      "closed_mailbox_raised_flag") echo -n "📫" ;;
      "closed_umbrella") echo -n "🌂" ;;
      "cloud_with_lightning") echo -n "🌩" ;;
      "cloud_with_rain") echo -n "🌧" ;;
      "cloud_with_snow") echo -n "🌨" ;;
      "cloud_with_tornado") echo -n "🌪" ;;
      "clover") echo -n "🍀" ;;
      "clown") echo -n "🤡" ;;
      "coat") echo -n "🧥" ;;
      "coconut") echo -n "🥥" ;;
      "coctail") echo -n "🍸" ;;
      "collision") echo -n "💥" ;;
      "compass") echo -n "🧭" ;;
      "confetti_ball") echo -n "🎊" ;;
      "confounded_face") echo -n "😖" ;;
      "confused_face") echo -n "😕" ;;
      "construction_worker") echo -n "👷" ;;
      "controls") echo -n "🎛" ;;
      "contruction_sign") echo -n "🚧" ;;
      "cooked_rice") echo -n "🍚" ;;
      "cookie") echo -n "🍪" ;;
      "cooking") echo -n "🍳" ;;
      "couch_and_lamp") echo -n "🛋" ;;
      "cow") echo -n "🐄" ;;
      "cow_face") echo -n "🐮" ;;
      "crab") echo -n "🦀" ;;
      "credit_card") echo -n "💳" ;;
      "cresent_moon") echo -n "🌙" ;;
      "cricket") echo -n "🦗" ;;
      "cricket") echo -n "🏏" ;;
      "crocodile") echo -n "🐊" ;;
      "croissant") echo -n "🥐" ;;
      "crosse_flags") echo -n "🎌" ;;
      "cross_pomme") echo -n "🕂" ;;
      "crown") echo -n "👑" ;;
      "crutch") echo -n "🩼" ;;
      "crying_face") echo -n "😢" ;;
      "crystal_ball") echo -n "🔮" ;;
      "cucumber") echo -n "🥒" ;;
      "cupcake") echo -n "🧁" ;;
      "cup_with_straw") echo -n "🥤" ;;
      "curling") echo -n "🥌" ;;
      "curly_hair") echo -n "🦱" ;;
      "currency_exchange") echo -n "💱" ;;
      "curry_and_rice") echo -n "🍛" ;;
      "custard") echo -n "🍮" ;;
      "customs") echo -n "🛃" ;;
      "cut_of_meat") echo -n "🥩" ;;
      "cyclone") echo -n "🌀" ;;
      "dancer") echo -n "💃" ;;
      "dango") echo -n "🍡" ;;
      "dash") echo -n "💨" ;;
      "deaf") echo -n "🧏" ;;
      "decidous_tre") echo -n "🌳" ;;
      "decorated_notebook") echo -n "📔" ;;
      "deer") echo -n "🦌" ;;
      "delivery_truck") echo -n "🚚" ;;
      "derelict_building") echo -n "🏚" ;;
      "descending_notes") echo -n "🎝" ;;
      "desert") echo -n "🏜" ;;
      "desert_island") echo -n "🏝" ;;
      "detective_or_spy") echo -n "🕵" ;;
      "diamond") echo -n "💠" ;;
      "direct_hit") echo -n "🎯" ;;
      "disappointed_but_relieved_face") echo -n "😥" ;;
      "disappointed_face") echo -n "😞" ;;
      "diskos") echo -n "🥏" ;;
      "diving") echo -n "🤿" ;;
      "dizzy") echo -n "💫" ;;
      "dizzy_face") echo -n "😵" ;;
      "dna") echo -n "🧬" ;;
      "doble_vertical_bars") echo -n "⏸" ;;
      "dodo") echo -n "🦤" ;;
      "dog") echo -n "🐕" ;;
      "dog_face") echo -n "🐶" ;;
      "dollar_sign") echo -n "💲" ;;
      "dolphin") echo -n "🐬" ;;
      "do_not_litter") echo -n "🚯" ;;
      "door") echo -n "🚪" ;;
      "doughnut") echo -n "🍩" ;;
      "down_double_triangle") echo -n "⏬" ;;
      "down_red_triangle") echo -n "🔻" ;;
      "down_triangle_small") echo -n "⏷" ;;
      "down_triangle") echo -n "🔽" ;;
      "downwards_trend") echo -n "📉" ;;
      "dragon") echo -n "🐉" ;;
      "dragon_face") echo -n "🐲" ;;
      "dress") echo -n "👗" ;;
      "dromedary") echo -n "🐪" ;;
      "droplet") echo -n "💧" ;;
      "drums") echo -n "🥁" ;;
      "duck") echo -n "🦆" ;;
      "dumpling") echo -n "🥟" ;;
      "dvd") echo -n "📀" ;;
      "eagle") echo -n "🦅" ;;
      "ear") echo -n "👂" ;;
      "ear_of_maize") echo -n "🌽" ;;
      "ear_of_rice") echo -n "🌾" ;;
      "earth_africa") echo -n "🌍" ;;
      "earth_americas") echo -n "🌎" ;;
      "earth_asia") echo -n "🌏" ;;
      "egg") echo -n "🥚" ;;
      "electrick_torch") echo -n "🔦" ;;
      "elephant") echo -n "🐘" ;;
      "elf") echo -n "🧝" ;;
      "e-mail") echo -n "📧" ;;
      "end_with_arrow") echo -n "🔚" ;;
      "envelope") echo -n "🖂" ;;
      "envelope_incoming") echo -n "📨" ;;
      "envelope_with_down_arrow") echo -n "📩" ;;
      "envelope_with_lightning") echo -n "🖄" ;;
      "evergreen_tree") echo -n "🌲" ;;
      "expressionless_face") echo -n "😑" ;;
      "extraterrestial") echo -n "👽" ;;
      "eye") echo -n "👁" ;;
      "eyeglasses") echo -n "👓" ;;
      "eyes") echo -n "👀" ;;
      "face_massage") echo -n "💆" ;;
      "face_palm") echo -n "🤦" ;;
      "face_savouring_delicious_food") echo -n "😋" ;;
      "face_screaming_in_fear") echo -n "😱" ;;
      "face_throwing_a_kiss") echo -n "😘" ;;
      "face_with_cold_sweat") echo -n "😓" ;;
      "face_with_look_of_triumph") echo -n "😤" ;;
      "face_with_medical_mask") echo -n "😷" ;;
      "face_with_open_mouth_and_cold_sweat") echo -n "😰" ;;
      "face_with_open_mouth") echo -n "😮" ;;
      "face_without_mouth") echo -n "😶" ;;
      "face_with_stuck-out_tongue_and_tightly-closed_eyes") echo -n "😝" ;;
      "face_with_stuck-out_tongue_and_winking_eye") echo -n "😜" ;;
      "face_with_stuck-out_tongue") echo -n "😛" ;;
      "face_with_tears_of_joy") echo -n "😂" ;;
      "factory") echo -n "🏭" ;;
      "fairy") echo -n "🧚" ;;
      "falafel") echo -n "🧆" ;;
      "fallen_leaf") echo -n "🍂" ;;
      "family") echo -n "👪" ;;
      "father_christmas") echo -n "🎅" ;;
      "fax") echo -n "📠" ;;
      "fearful_face") echo -n "😨" ;;
      "fencer") echo -n "🤺" ;;
      "ferris_wheel") echo -n "🎡" ;;
      "field_hockey") echo -n "🏑" ;;
      "file_folder") echo -n "📁" ;;
      "film_frames") echo -n "🎞" ;;
      "film_projector") echo -n "📽" ;;
      "fircracker") echo -n "🧨" ;;
      "fire") echo -n "🔥" ;;
      "fire_engine") echo -n "🚒" ;;
      "fire_extinguiser") echo -n "🧯" ;;
      "fireworks") echo -n "🎆" ;;
      "firework_sparkler") echo -n "🎇" ;;
      "first_place") echo -n "🥇" ;;
      "first_quarter_moon") echo -n "🌓" ;;
      "first_quarter_moon_face") echo -n "🌛" ;;
      "fish_cake") echo -n "🍥" ;;
      "fish") echo -n "🐙" ;;
      "fish") echo -n "🐟" ;;
      "fishing") echo -n "🎣" ;;
      "flamingo") echo -n "🦩" ;;
      "flat_shoe") echo -n "🥿" ;;
      "flexed_biceps") echo -n "💪" ;;
      "floppy_disk") echo -n "💾" ;;
      "flower_bouquet") echo -n "🎕" ;;
      "flushed_face") echo -n "😳" ;;
      "flying_envelope") echo -n "🖅" ;;
      "fog") echo -n "🌫" ;;
      "foggy") echo -n "🌁" ;;
      "folded_hands") echo -n "🙏" ;;
      "foodpot") echo -n "🍲" ;;
      "foot") echo -n "🦶" ;;
      "footprints") echo -n "👣" ;;
      "fork_and_knife") echo -n "🍴" ;;
      "fork,_knife_and_plate") echo -n "🍽" ;;
      "fortune_cookie") echo -n "🥠" ;;
      "fountain") echo -n "⛲" ;;
      "fox_face") echo -n "🦊" ;;
      "french_fries") echo -n "🍟" ;;
      "fried_shrimp") echo -n "🍤" ;;
      "frog_face") echo -n "🐸" ;;
      "front_baby_chick") echo -n "🐥" ;;
      "frowning") echo -n "🙍" ;;
      "frowning_face_with_open_mouth") echo -n "😦" ;;
      "fuel_pump") echo -n "⛽" ;;
      "full_moon") echo -n "🌕" ;;
      "full_moon_face") echo -n "🌝" ;;
      "game_die") echo -n "🎲" ;;
      "garlic") echo -n "🧄" ;;
      "gem_stone") echo -n "💎" ;;
      "genie") echo -n "🧞" ;;
      "ghost") echo -n "👻" ;;
      "giraffe_face") echo -n "🦒" ;;
      "girl") echo -n "👧" ;;
      "girls") echo -n "🛊" ;;
      "globe_meridians") echo -n "🌐" ;;
      "gloves") echo -n "🧤" ;;
      "glowing_star") echo -n "🌟" ;;
      "goal_net") echo -n "🥅" ;;
      "goat") echo -n "🐐" ;;
      "goggles") echo -n "🥽" ;;
      "golf") echo -n "⛳" ;;
      "golfer") echo -n "🏌" ;;
      "gorilla") echo -n "🦍" ;;
      "graduation_cap") echo -n "🎓" ;;
      "grapes") echo -n "🍇" ;;
      "green_apple") echo -n "🍏" ;;
      "green_book") echo -n "📗" ;;
      "green_heart") echo -n "💚" ;;
      "green_salad") echo -n "🥗" ;;
      "grimacing_face") echo -n "😬" ;;
      "grinning_face") echo -n "😀" ;;
      "grinning_face_with_smiling_eyes") echo -n "😁" ;;
      "growing_heart") echo -n "💗" ;;
      "guardsman") echo -n "💂" ;;
      "guide_dog") echo -n "🦮" ;;
      "guitar") echo -n "🎸" ;;
      "haircut") echo -n "💇" ;;
      "half-circled_cross_pomme") echo -n "🕁" ;;
      "halfmoon") echo -n "🌙" ;;
      "hamburger") echo -n "🍔" ;;
      "hammer") echo -n "🔨" ;;
      "hamster_face") echo -n "🐹" ;;
      "hand10") echo -n "👉" ;;
      "hand11") echo -n "🖕" ;;
      "hand12") echo -n "✊" ;;
      "hand13") echo -n "👊" ;;
      "hand14") echo -n "👍" ;;
      "hand15") echo -n "👎" ;;
      "hand16") echo -n "🤛" ;;
      "hand17") echo -n "🤜" ;;
      "hand18") echo -n "✌" ;;
      "hand19") echo -n "👌" ;;
      "hand1") echo -n "✋" ;;
      "hand20") echo -n "🤏" ;;
      "hand21") echo -n "🤘" ;;
      "hand22") echo -n "🤙" ;;
      "hand23") echo -n "🤞" ;;
      "hand24") echo -n "🤟" ;;
      "hand25") echo -n "✍" ;;
      "hand26") echo -n "👏" ;;
      "hand27") echo -n "👐" ;;
      "hand28") echo -n "💅" ;;
      "hand29") echo -n "🤝" ;;
      "hand2") echo -n "👋" ;;
      "hand30") echo -n "🤝" ;;
      "hand31") echo -n "🤲" ;;
      "hand32") echo -n "🤳" ;;
      "hand3") echo -n "🖐" ;;
      "hand4") echo -n "🖖" ;;
      "hand5") echo -n "🤚" ;;
      "hand6") echo -n "☝" ;;
      "hand7") echo -n "👆" ;;
      "hand8") echo -n "👇" ;;
      "hand9") echo -n "👈" ;;
      "handbag") echo -n "👜" ;;
      "handball") echo -n "🤾" ;;
      "hatching_chick") echo -n "🐣" ;;
      "headphone") echo -n "🎧" ;;
      "headsharf") echo -n "🧕" ;;
      "hearing_aid") echo -n "🦻" ;;
      "hear_no_evil") echo -n "🙉" ;;
      "heart_decoration") echo -n "💟" ;;
      "heart") echo -n "🧡" ;;
      "heart_gray") echo -n "🖤" ;;
      "heart_pink") echo -n "❤" ;;
      "heart_with_arrow") echo -n "💘" ;;
      "heart_with_ribbon") echo -n "💝" ;;
      "heart_with_tip") echo -n "🎔" ;;
      "hedgehog") echo -n "🦔" ;;
      "helicopter") echo -n "🚁" ;;
      "helpdesk") echo -n "💁" ;;
      "herb") echo -n "🌿" ;;
      "hibiscus") echo -n "🌺" ;;
      "high_brightness") echo -n "🔆" ;;
      "high-heeled_shoe") echo -n "👠" ;;
      "high-speed_train") echo -n "🚄" ;;
      "high-speed_train") echo -n "🚅" ;;
      "hiking_boot") echo -n "🥾" ;;
      "hindu_temple") echo -n "🛕" ;;
      "hippopotamus") echo -n "🦛" ;;
      "hocho") echo -n "🔪" ;;
      "hole") echo -n "🕳" ;;
      "honeybee") echo -n "🐝" ;;
      "honey_pot") echo -n "🍯" ;;
      "horce_ricing") echo -n "🏇" ;;
      "horse") echo -n "🐎" ;;
      "horse_face") echo -n "🐴" ;;
      "hostpital") echo -n "🏥" ;;
      "hot_beverage") echo -n "☕" ;;
      "hot_dog") echo -n "🌭" ;;
      "hotel") echo -n "🏨" ;;
      "hotel") echo -n "🏬" ;;
      "hot_pepper") echo -n "🌶" ;;
      "house_buildings") echo -n "🏘" ;;
      "house") echo -n "🏠" ;;
      "house_with_garden") echo -n "🏡" ;;
      "hundred_points") echo -n "💯" ;;
      "hushed_face") echo -n "😯" ;;
      "icecream_cone") echo -n "🎉" ;;
      "icecream_sunday") echo -n "🍨" ;;
      "ice") echo -n "🧊" ;;
      "ice_hockey") echo -n "🏒" ;;
      "imp") echo -n "👿" ;;
      "inbox") echo -n "📥" ;;
      "information") echo -n "🛈" ;;
      "inout_box") echo -n "🛗" ;;
      "input_capital_letters") echo -n "🔠" ;;
      "input_letters") echo -n "🔤" ;;
      "input_numbers") echo -n "🔢" ;;
      "input_small_letters") echo -n "🔡" ;;
      "input_symbols") echo -n "🔣" ;;
      "island") echo -n "🏝️" ;;
      "izakaya_bar") echo -n "🏮" ;;
      "jack-o_lantern") echo -n "🎃" ;;
      "japan_castle") echo -n "🏯" ;;
      "japanese_dolls") echo -n "🎎" ;;
      "japanese_goblin") echo -n "👺" ;;
      "japanese_ogre") echo -n "👹" ;;
      "japan_post") echo -n "🏣" ;;
      "japan_silhoette") echo -n "🗾" ;;
      "japnese_beginner") echo -n "🔰" ;;
      "jeans") echo -n "👖" ;;
      "joystick") echo -n "🕹" ;;
      "juggling") echo -n "🤹" ;;
      "kaaba") echo -n "🕋" ;;
      "kangaroo") echo -n "🦘" ;;
      "keyboard") echo -n "🎹" ;;
      "keyboard_with_jacks") echo -n "🎘" ;;
      "key") echo -n "🔑" ;;
      "keykap_ten") echo -n "🔟" ;;
      "kick_scooter") echo -n "🛴" ;;
      "kimono") echo -n "👘" ;;
      "kiss") echo -n "💏" ;;
      "kissing_face") echo -n "😗" ;;
      "kissing_face_with_closed_eyes") echo -n "😚" ;;
      "kissing_face_with_smiling_eyes") echo -n "😙" ;;
      "kiss_mark") echo -n "💋" ;;
      "kite") echo -n "🪁" ;;
      "kiwi") echo -n "🥝" ;;
      "koala") echo -n "🐨" ;;
      "lab_coat") echo -n "🥼" ;;
      "label") echo -n "🏷" ;;
      "lacrosse") echo -n "🥍" ;;
      "lady_beetle") echo -n "🐞" ;;
      "large_blue_circle") echo -n "🔵" ;;
      "large_blue_diamond") echo -n "🔷" ;;
      "large_orange_diamond") echo -n "🔶" ;;
      "large_red_circle") echo -n "🔴" ;;
      "last_quarter_moon") echo -n "🌗" ;;
      "last_quarter_moon_face") echo -n "🌜" ;;
      "leaf_in_wind") echo -n "🍃" ;;
      "leafy_green") echo -n "🥬" ;;
      "ledger") echo -n "📒" ;;
      "left_anger_bubble") echo -n "🗮" ;;
      "left_double_triangle") echo -n "⏪" ;;
      "left_double_triangle_with_bar") echo -n "⏮" ;;
      "left_luggage") echo -n "🛅" ;;
      "left_magnifying_glass") echo -n "🔍" ;;
      "left_semicircle") echo -n "🕃" ;;
      "left_speach_bubble") echo -n "🗩" ;;
      "left_telephone_receiver") echo -n "🕻" ;;
      "left_thought_bubble") echo -n "🗬" ;;
      "left_triangle") echo -n "⏴" ;;
      "leg") echo -n "🦵" ;;
      "lemon") echo -n "🍋" ;;
      "leopard") echo -n "🐆" ;;
      "light_bulb") echo -n "💡" ;;
      "lightning_mood_bubble") echo -n "🗱" ;;
      "lightning_mood") echo -n "🗲" ;;
      "light_rail") echo -n "🚈" ;;
      "link") echo -n "🔗" ;;
      "lion_face") echo -n "🦁" ;;
      "lipstick") echo -n "💄" ;;
      "lizard") echo -n "🦎" ;;
      "llama") echo -n "🦙" ;;
      "lobster") echo -n "🦞" ;;
      "lock") echo -n "🔒" ;;
      "lock_with_key") echo -n "🔐" ;;
      "lock_with_pen") echo -n "🔏" ;;
      "lollipop") echo -n "🍭" ;;
      "lotion_bottle") echo -n "🧴" ;;
      "lotus_position") echo -n "🧘" ;;
      "loudly_crying_face") echo -n "😭" ;;
      "loudspeaker") echo -n "📢" ;;
      "love") echo -n "💑" ;;
      "love_hotel") echo -n "🏩" ;;
      "love_letter") echo -n "💌" ;;
      "low_brightness") echo -n "🔅" ;;
      "lower_crayon") echo -n "🖍" ;;
      "lower_fountain_pen") echo -n "🖋" ;;
      "lower_paintbrush") echo -n "🖌" ;;
      "lower_pencil") echo -n "🖉" ;;
      "luggage") echo -n "🧳" ;;
      "macic_wand") echo -n "🪄" ;;
      "mage") echo -n "🧙" ;;
      "magnet") echo -n "🧲" ;;
      "mammoth") echo -n "🦣" ;;
      "man_and_woman") echo -n "👫" ;;
      "man_dancing") echo -n "🕺" ;;
      "man") echo -n "👨" ;;
      "mango") echo -n "🥭" ;;
      "man_gua_pi_mao") echo -n "👲" ;;
      "man_in_tuxedo") echo -n "🤵" ;;
      "mans_shoe") echo -n "👞" ;;
      "mantelpiece_clock") echo -n "🕰" ;;
      "man_turban") echo -n "👳" ;;
      "maple_leaf") echo -n "🍁" ;;
      "marks_chapter") echo -n "🕅" ;;
      "martial_arts") echo -n "🥋" ;;
      "mate") echo -n "🧉" ;;
      "meat_on_bone") echo -n "🍖" ;;
      "mecanical_leg") echo -n "🦿" ;;
      "mechanical_arm") echo -n "🦾" ;;
      "megaphone") echo -n "📣" ;;
      "melon") echo -n "🍈" ;;
      "memo") echo -n "📝" ;;
      "men") echo -n "🚹" ;;
      "menorah") echo -n "🕎" ;;
      "merperson") echo -n "🧜" ;;
      "metro") echo -n "🚇" ;;
      "microbe") echo -n "🦠" ;;
      "microphone") echo -n "🎤" ;;
      "microphone2") echo -n "🎙" ;;
      "microscope") echo -n "🔬" ;;
      "military_medal") echo -n "🎖" ;;
      "milk_glass") echo -n "🥛" ;;
      "milky_way") echo -n "🌌" ;;
      "minibus") echo -n "🚐" ;;
      "mini_disk") echo -n "💽" ;;
      "mobile_phone") echo -n "📱" ;;
      "mobile_phone_off") echo -n "📴" ;;
      "mobile_phone_vibrating") echo -n "📳" ;;
      "mobile_phone_with_arrow") echo -n "📲" ;;
      "money_bag") echo -n "💰" ;;
      "money_with_wings") echo -n "💸" ;;
      "monkey") echo -n "🐒" ;;
      "monkey_face") echo -n "🐵" ;;
      "monorail") echo -n "🚝" ;;
      "mood_bubble") echo -n "🗰" ;;
      "moon_cake") echo -n "🥮" ;;
      "moon_ceremony") echo -n "🎑" ;;
      "mosque") echo -n "🕌" ;;
      "mosquito") echo -n "🦟" ;;
      "mother_christmas") echo -n "🤶" ;;
      "motorcycle") echo -n "🏍" ;;
      "motor_scooter") echo -n "🛵" ;;
      "mountain_bicyclist") echo -n "🚵" ;;
      "mountain_cableway") echo -n "🚠" ;;
      "mountain_railway") echo -n "🚞" ;;
      "mount_fuji") echo -n "🗻" ;;
      "mouse") echo -n "🐁" ;;
      "mouse_face") echo -n "🐭" ;;
      "mouth") echo -n "👄" ;;
      "movie_camera") echo -n "🎥" ;;
      "moyai") echo -n "🗿" ;;
      "mushroom") echo -n "🍄" ;;
      "nail_polish") echo -n "💅" ;;
      "name_badge") echo -n "📛" ;;
      "national_park") echo -n "🏞" ;;
      "native_hut") echo -n "🛖" ;;
      "nazar_amulet") echo -n "🧿" ;;
      "necktie") echo -n "👔" ;;
      "nesting_dolls") echo -n "🪆" ;;
      "neutral_face") echo -n "😐" ;;
      "new_moon") echo -n "🌑" ;;
      "new_moon_face") echo -n "🌚" ;;
      "newspaper") echo -n "📰" ;;
      "night_with_stars") echo -n "🌃" ;;
      "no_bell") echo -n "🔕" ;;
      "no_bicycles") echo -n "🚳" ;;
      "no_entry") echo -n "⛔" ;;
      "no_entry") echo -n "🚫" ;;
      "no_good") echo -n "🙅" ;;
      "no_mobile_phones") echo -n "📵" ;;
      "non-potable_water") echo -n "🚱" ;;
      "no_one_under_18") echo -n "🔞" ;;
      "no_pedrestians") echo -n "🚷" ;;
      "no_piracy") echo -n "🕲" ;;
      "nose") echo -n "👃" ;;
      "no_smoking") echo -n "🚭" ;;
      "notebook") echo -n "📓" ;;
      "note") echo -n "🎵" ;;
      "notes") echo -n "🎶" ;;
      "nut_and_bolt") echo -n "🔩" ;;
      "octagon") echo -n "🛑" ;;
      "oden") echo -n "🍢" ;;
      "office_building") echo -n "🏢" ;;
      "ok") echo -n "🙆" ;;
      "older_adult") echo -n "🧓" ;;
      "older_man") echo -n "👴" ;;
      "older_woman") echo -n "👵" ;;
      "om_symbol") echo -n "🕉" ;;
      "oncoming_automobile") echo -n "🚘" ;;
      "oncoming_bus") echo -n "🚍" ;;
      "oncoming_police") echo -n "🚔" ;;
      "oncoming_taxi") echo -n "🚖" ;;
      "onion") echo -n "🧅" ;;
      "on_with_arrows") echo -n "🔛" ;;
      "open_book") echo -n "📖" ;;
      "open_file_folder") echo -n "📂" ;;
      "open_lock") echo -n "🔓" ;;
      "open_mailbox_low_flag") echo -n "📬" ;;
      "open_mailbox_raised_flag") echo -n "📭" ;;
      "optical_disk") echo -n "💿" ;;
      "orange_book") echo -n "📙" ;;
      "orangutan") echo -n "🦧" ;;
      "otter") echo -n "🦦" ;;
      "outbox") echo -n "📤" ;;
      "outline_arch") echo -n "🛤" ;;
      "outline_arch_outline") echo -n "🛣" ;;
      "outline_boat") echo -n "🛳" ;;
      "outline_box") echo -n "🗃" ;;
      "outline_calendar") echo -n "🗓" ;;
      "outline_disk") echo -n "🛢" ;;
      "outline_file") echo -n "🗂" ;;
      "outline_filing_cabinet") echo -n "🗄" ;;
      "outline_holepunch") echo -n "🗜" ;;
      "outline_key") echo -n "🗝" ;;
      "outline_monalisa") echo -n "🖼" ;;
      "outline_notepad") echo -n "🗒" ;;
      "outline_paintbrush") echo -n "🛓" ;;
      "outline_pizza") echo -n "🗞" ;;
      "outline_plane1") echo -n "🛦" ;;
      "outline_plane2") echo -n "🛧" ;;
      "outline_plane3") echo -n "🛨" ;;
      "outline_plane4") echo -n "🛩" ;;
      "outline_plane5") echo -n "🛪" ;;
      "outline_plane6") echo -n "🛫" ;;
      "outline_plane7") echo -n "🛬" ;;
      "outline_projector") echo -n "🗳" ;;
      "outline_satelite") echo -n "🛰" ;;
      "outline_sheild") echo -n "🛡" ;;
      "outline_spanner_hammer") echo -n "🛠" ;;
      "outline_speaking") echo -n "🗣" ;;
      "outline_syringe") echo -n "🗡" ;;
      "outline_tower") echo -n "🛔" ;;
      "outline_train") echo -n "🛲" ;;
      "outline_trash") echo -n "🗑" ;;
      "outline_truck") echo -n "🛱" ;;
      "owl") echo -n "🦉" ;;
      "ox") echo -n "🐂" ;;
      "oyster") echo -n "🦪" ;;
      "package") echo -n "📦" ;;
      "page_facing_up") echo -n "📄" ;;
      "pager") echo -n "📟" ;;
      "page_with_curl") echo -n "📃" ;;
      "palm_tree") echo -n "🌴" ;;
      "pancakes") echo -n "🥞" ;;
      "panda_face") echo -n "🐼" ;;
      "paperclip") echo -n "📎" ;;
      "paperclips") echo -n "🖇" ;;
      "paper_roll") echo -n "🧻" ;;
      "parachute") echo -n "🪂" ;;
      "parrot") echo -n "🦜" ;;
      "party_popper") echo -n "🎉" ;;
      "passport_control") echo -n "🛂" ;;
      "paw_prints") echo -n "🐾" ;;
      "pc") echo -n "💻" ;;
      "peace_dove") echo -n "🕊" ;;
      "peach") echo -n "🍑" ;;
      "peacock") echo -n "🦚" ;;
      "peanuts") echo -n "🥜" ;;
      "pear") echo -n "🍐" ;;
      "pedestrian") echo -n "🚶" ;;
      "penguin") echo -n "🐧" ;;
      "pen_over_envelope") echo -n "🖆" ;;
      "pensive_face") echo -n "😔" ;;
      "penthatlon") echo -n "🤻" ;;
      "performing_art") echo -n "🎭" ;;
      "persevering_face") echo -n "😣" ;;
      "person_blond") echo -n "👱" ;;
      "person_kneeling") echo -n "🧎" ;;
      "person_standing") echo -n "🧍" ;;
      "petri_dish") echo -n "🧫" ;;
      "pie") echo -n "🥧" ;;
      "pig") echo -n "🐖" ;;
      "pig_face") echo -n "🐷" ;;
      "pig_nose") echo -n "🐽" ;;
      "pile_of_poo") echo -n "💩" ;;
      "pill") echo -n "💊" ;;
      "pinata") echo -n "🪅" ;;
      "pineapple") echo -n "🍍" ;;
      "pine_decoration") echo -n "🎍" ;;
      "pistol") echo -n "🔫" ;;
      "pizza") echo -n "🍕" ;;
      "place_of_worship") echo -n "🛐" ;;
      "planet_earth") echo -n "🌍" ;;
      "planet_gray") echo -n "🌑" ;;
      "planet_red") echo -n "🔴" ;;
      "planet_tblue") echo -n "🔵" ;;
      "plaster") echo -n "🩹" ;;
      "playing_cards") echo -n "🎴" ;;
      "police_car") echo -n "🚓" ;;
      "police_car_light") echo -n "🚨" ;;
      "police") echo -n "👮" ;;
      "poodle") echo -n "🐩" ;;
      "popcorn") echo -n "🍿" ;;
      "portable_stereo") echo -n "📾" ;;
      "posbox") echo -n "📮" ;;
      "postal_horn") echo -n "📯" ;;
      "post_office") echo -n "🏤" ;;
      "potable_water") echo -n "🚰" ;;
      "potato") echo -n "🥔" ;;
      "pouch") echo -n "👝" ;;
      "poultry_leg") echo -n "🍗" ;;
      "pouting_face") echo -n "😡" ;;
      "pouting_face") echo -n "🙎" ;;
      "power_plug") echo -n "🔌" ;;
      "prayer_beads") echo -n "📿" ;;
      "pregnant") echo -n "🤰" ;;
      "pretzel") echo -n "🥨" ;;
      "prince") echo -n "🤴" ;;
      "princess") echo -n "👸" ;;
      "probing_cane") echo -n "🦯" ;;
      "prohibited") echo -n "🛇" ;;
      "purple_heart") echo -n "💜" ;;
      "purse") echo -n "👛" ;;
      "pushpin") echo -n "📌" ;;
      "put_litter") echo -n "🚮" ;;
      "puzzle") echo -n "🧩" ;;
      "rabbit") echo -n "🐇" ;;
      "rabbit_face") echo -n "🐰" ;;
      "raccoon") echo -n "🦝" ;;
      "racing_car") echo -n "🏎" ;;
      "racing_motorcycle") echo -n "🏍" ;;
      "radioactive") echo -n "☢️ " ;;
      "radio_button") echo -n "🔘" ;;
      "radio") echo -n "📻" ;;
      "railway_car") echo -n "🚃" ;;
      "rainbow") echo -n "🌈" ;;
      "raised_hand") echo -n "🙋" ;;
      "ram") echo -n "🐏" ;;
      "rat") echo -n "🐀" ;;
      "receipt") echo -n "🧾" ;;
      "recreation_vehicle") echo -n "🚙" ;;
      "red_apple") echo -n "🍎" ;;
      "red_gift_envelope") echo -n "🧧" ;;
      "red_hair") echo -n "🦰" ;;
      "red_wine") echo -n "🍷" ;;
      "relieved_face") echo -n "😌" ;;
      "reminder_ribbon") echo -n "🎗" ;;
      "restroom") echo -n "🚻" ;;
      "revolving_hearts") echo -n "💞" ;;
      "rhinoceros") echo -n "🦏" ;;
      "ribbon") echo -n "🎀" ;;
      "rice_ball") echo -n "🍙" ;;
      "rice_cracker") echo -n "🍘" ;;
      "rifle") echo -n "🥆" ;;
      "right_anger_bubble") echo -n "🗯" ;;
      "right_double_triangle") echo -n "⏩" ;;
      "right_double_triangle_with_bar") echo -n "⏭" ;;
      "right_magnifying_glass") echo -n "🔎" ;;
      "right_semicircle") echo -n "🕄" ;;
      "right_speach_bubble") echo -n "🗨" ;;
      "right_speaker") echo -n "🕨" ;;
      "right_telephone_receiver") echo -n "🕽" ;;
      "right_thought_bubble") echo -n "🗭" ;;
      "right_triangle") echo -n "⏵" ;;
      "right_triangle_with_bars") echo -n "⏯" ;;
      "ring") echo -n "💍" ;;
      "ringing_bell") echo -n "🕭" ;;
      "robot") echo -n "🤖" ;;
      "robot") echo -n "🤖" ;;
      "rocket") echo -n "🚀" ;;
      "roller_coaster") echo -n "🎢" ;;
      "roller_skate") echo -n "🛼" ;;
      "rooster") echo -n "🐓" ;;
      "rosed_potato") echo -n "🍠" ;;
      "rose") echo -n "🌹" ;;
      "rose") echo -n "🌹" ;;
      "round_pushpin") echo -n "📍" ;;
      "rowboat") echo -n "🚣" ;;
      "rugby_football") echo -n "🏉" ;;
      "runner") echo -n "🏃" ;;
      "running_shirt") echo -n "🎽" ;;
      "safety_pin") echo -n "🧷" ;;
      "safety_vest") echo -n "🦺" ;;
      "sake") echo -n "🍶" ;;
      "salt_shaker") echo -n "🧂" ;;
      "sandwithch") echo -n "🥪" ;;
      "sari") echo -n "🥻" ;;
      "satellite_antenna") echo -n "📡" ;;
      "saturn") echo -n "🪐" ;;
      "sauropod") echo -n "🦕" ;;
      "saxophone") echo -n "🎷" ;;
      "scarf") echo -n "🧣" ;;
      "school") echo -n "🏫" ;;
      "school_satchel") echo -n "🎒" ;;
      "scooter") echo -n "🛴" ;;
      "score") echo -n "🎼" ;;
      "scorpion") echo -n "🦂" ;;
      "scroll") echo -n "📜" ;;
      "seal") echo -n "🦭" ;;
      "seat") echo -n "💺" ;;
      "second_place") echo -n "🥈" ;;
      "seedling") echo -n "🌱" ;;
      "see_no_evil") echo -n "🙈" ;;
      "shallow_pan") echo -n "🥘" ;;
      "shark") echo -n "🦈" ;;
      "shaved_ice") echo -n "🍧" ;;
      "sheep") echo -n "🐑" ;;
      "ship") echo -n "🚢" ;;
      "shooting_star") echo -n "🌠" ;;
      "shopping_bags") echo -n "🛍" ;;
      "shopping_trolley") echo -n "🛒" ;;
      "shortcake") echo -n "🍰" ;;
      "shorts") echo -n "🩳" ;;
      "shower") echo -n "🚿" ;;
      "shrimp") echo -n "🦐" ;;
      "shrug") echo -n "🤷" ;;
      "six_pointed_star") echo -n "🔯" ;;
      "skateboard") echo -n "🛹" ;;
      "skull") echo -n "💀" ;;
      "skunk") echo -n "🦨" ;;
      "slalom") echo -n "🎿" ;;
      "sled") echo -n "🛷" ;;
      "sleeping_accomodation") echo -n "🛌" ;;
      "sleeping") echo -n "💤" ;;
      "sleeping_face") echo -n "😴" ;;
      "sleepy_face") echo -n "😪" ;;
      "slider") echo -n "🎚" ;;
      "sloth") echo -n "🦥" ;;
      "slot_machine") echo -n "🎰" ;;
      "small_blue_diamond") echo -n "🔹" ;;
      "small_orange_diamond") echo -n "🔸" ;;
      "smiley") echo -n "😄" ;;
      "smiling_face_with_halo") echo -n "😇" ;;
      "smiling_face_with_heart-shaped_eyes") echo -n "😍" ;;
      "smiling_face_with_horns") echo -n "😈" ;;
      "smiling_face_with_open_mouth_and_cold_sweat") echo -n "😅" ;;
      "smiling_face_with_open_mouth_and_smiling_eyes") echo -n "😄" ;;
      "smiling_face_with_open_mouth_and_tightly-closed_eyes") echo -n "😆" ;;
      "smiling_face_with_open_mouth") echo -n "😃" ;;
      "smiling_face_with_smiling_eyes") echo -n "😊" ;;
      "smiling_face_with_sunglasses") echo -n "😎" ;;
      "smirking_face") echo -n "😏" ;;
      "smoking") echo -n "🚬" ;;
      "snail") echo -n "🐌" ;;
      "snake") echo -n "🐍" ;;
      "snowboarder") echo -n "🏂" ;;
      "snow_capped_mountain") echo -n "🏔" ;;
      "snowflake") echo -n "❄" ;;
      "snowflake") echo -n "❅" ;;
      "snowflake") echo -n "❆" ;;
      "snowman") echo -n "⛄" ;;
      "soap_bar") echo -n "🧼" ;;
      "soccer_ball") echo -n "⚽" ;;
      "socs") echo -n "🧦" ;;
      "softball") echo -n "🥎" ;;
      "soft_ice") echo -n "🍦" ;;
      "soon_with_arrow") echo -n "🔜" ;;
      "space_invader") echo -n "👾" ;;
      "spaghetti") echo -n "🍝" ;;
      "sparkling_heart") echo -n "💖" ;;
      "sparkling_wine") echo -n "🍾" ;;
      "speaker") echo -n "🔈" ;;
      "speaker_off") echo -n "🔇" ;;
      "speaker_with_sound_wave") echo -n "🔉" ;;
      "speaker_with_sound_waves") echo -n "🔊" ;;
      "speaker_with_wave") echo -n "🕩" ;;
      "speaker_with_waves") echo -n "🕪" ;;
      "speak_no_evil") echo -n "🙊" ;;
      "speech_ballon") echo -n "💬" ;;
      "speedboat") echo -n "🚤" ;;
      "spiral_shell") echo -n "🐚" ;;
      "splashing_sweat") echo -n "💦" ;;
      "sponge") echo -n "🧽" ;;
      "spool_of_tread") echo -n "🧵" ;;
      "spoon") echo -n "🥄" ;;
      "sports_medal") echo -n "🏅" ;;
      "spouting_whale") echo -n "🐳" ;;
      "squid") echo -n "🦑" ;;
      "stadium") echo -n "🏟" ;;
      "stamped_envelope") echo -n "🖃" ;;
      "station") echo -n "🚉" ;;
      "statue_of_liberty") echo -n "🗽" ;;
      "steaming_bowl") echo -n "🍜" ;;
      "steam_locomotive") echo -n "🚂" ;;
      "steamy_room") echo -n "🧖" ;;
      "stethoscope") echo -n "🩺" ;;
      "store") echo -n "🏪" ;;
      "straight_ruler") echo -n "📏" ;;
      "strawberry") echo -n "🍓" ;;
      "stuffed_flatbread") echo -n "🥙" ;;
      "sun_behind_cloud") echo -n "⛅" ;;
      "sun") echo -n "☀" ;;
      "sun") echo -n "💥" ;;
      "sunflower") echo -n "🌻" ;;
      "sunglasses") echo -n "🕶" ;;
      "sunrise") echo -n "🌄" ;;
      "sunrise_over_sea") echo -n "🌅" ;;
      "sunset_over_buildings") echo -n "🌇" ;;
      "sun_with_face") echo -n "🌞" ;;
      "superhero") echo -n "🦸" ;;
      "supervillan") echo -n "🦹" ;;
      "surfer") echo -n "🏄" ;;
      "sushi") echo -n "🍣" ;;
      "suspension_railway") echo -n "🚟" ;;
      "swan") echo -n "🦢" ;;
      "swimmer") echo -n "🏊" ;;
      "swimsuit") echo -n "🩱" ;;
      "swords") echo -n "⚔️ " ;;
      "synagogue") echo -n "🕍" ;;
      "syringe") echo -n "💉" ;;
      "table_tennis") echo -n "🏓" ;;
      "taco") echo -n "🌮" ;;
      "takeout_box") echo -n "🥡" ;;
      "tanaba_tree") echo -n "🎋" ;;
      "tangerine") echo -n "🍊" ;;
      "taxi") echo -n "🚕" ;;
      "teacup") echo -n "🍵" ;;
      "tear-off_calendar") echo -n "📆" ;;
      "teddy_bear") echo -n "🧸" ;;
      "telephone_on_modem") echo -n "🖀" ;;
      "telephone_receiver") echo -n "📞" ;;
      "telephone_receiver_page") echo -n "🕼" ;;
      "telescope") echo -n "🔭" ;;
      "television") echo -n "📺" ;;
      "tennis") echo -n "🎾" ;;
      "tent") echo -n "⛺" ;;
      "test_tube") echo -n "🧪" ;;
      "thermometer") echo -n "🌡" ;;
      "third_place") echo -n "🥉" ;;
      "thong_sandal") echo -n "🩴" ;;
      "thought_ballon") echo -n "💭" ;;
      "three_speach_bubbles") echo -n "🗫" ;;
      "tick_green") echo -n "✅" ;;
      "ticket") echo -n "🎫" ;;
      "tickets") echo -n "🎟" ;;
      "tiger") echo -n "🐅" ;;
      "tiger_face") echo -n "🐯" ;;
      "tired_face") echo -n "😫" ;;
      "toilet") echo -n "🚽" ;;
      "tokyo_tower") echo -n "🗼" ;;
      "tomato") echo -n "🍅" ;;
      "tongue") echo -n "👅" ;;
      "toolbox") echo -n "🧰" ;;
      "tooth") echo -n "🦷" ;;
      "top_hat") echo -n "🎩" ;;
      "top_with_arrow") echo -n "🔝" ;;
      "tractor") echo -n "🚜" ;;
      "traffic_ligth_horizontal") echo -n "🚥" ;;
      "traffic_ligth_vertical") echo -n "🚦" ;;
      "train") echo -n "🚆" ;;
      "tram_car") echo -n "🚋" ;;
      "tram") echo -n "🚊" ;;
      "t-rex") echo -n "🦖" ;;
      "triangle") echo -n "🛆" ;;
      "triangular_flag") echo -n "🚩" ;;
      "triangular_ruler") echo -n "📐" ;;
      "trident_emblem") echo -n "🔱" ;;
      "trolleybus") echo -n "🚎" ;;
      "trophy") echo -n "🏆" ;;
      "tropical") echo -n "🍹" ;;
      "tropical_fish") echo -n "🐠" ;;
      "trumpet") echo -n "🎺" ;;
      "t-shirt") echo -n "👕" ;;
      "tulip") echo -n "🌷" ;;
      "tumbler_glass") echo -n "🥃" ;;
      "turkey") echo -n "🦃" ;;
      "turtle") echo -n "🐢" ;;
      "twisted_right_arrows") echo -n "🔀" ;;
      "two_hearts") echo -n "💕" ;;
      "two_men") echo -n "👬" ;;
      "two_speach_bubbles") echo -n "🗪" ;;
      "two_women") echo -n "👭" ;;
      "ufo") echo -n "🛸" ;;
      "umbrella") echo -n "☂" ;;
      "umbrella_rain") echo -n "☔" ;;
      "unamused_face") echo -n "😒" ;;
      "unicorn_face") echo -n "🦄" ;;
      "up_double_triangle") echo -n "⏫" ;;
      "up_red_triangle") echo -n "🔺" ;;
      "up_triangle_small") echo -n "⏶" ;;
      "up_triangle") echo -n "🔼" ;;
      "upwards_trend") echo -n "📈" ;;
      "upward_trend_yen") echo -n "💹" ;;
      "vampire") echo -n "🧛" ;;
      "video_camera") echo -n "📹" ;;
      "videocasette") echo -n "📼" ;;
      "video_game") echo -n "🎮" ;;
      "violin") echo -n "🎻" ;;
      "volcano") echo -n "🌋" ;;
      "volleyball") echo -n "🏐" ;;
      "vulcano") echo -n "🌋" ;;
      "waffle") echo -n "🧇" ;;
      "waining_cresent_moon") echo -n "🌘" ;;
      "waining_gibbous_moon") echo -n "🌖" ;;
      "water_buffalo") echo -n "🐃" ;;
      "watermelon") echo -n "🍉" ;;
      "water_polo") echo -n "🤽" ;;
      "water_wave") echo -n "🌊" ;;
      "waxing_cresent_moon") echo -n "🌒" ;;
      "waxing_gibbous_moon") echo -n "🌔" ;;
      "wc") echo -n "🚾" ;;
      "weary_face") echo -n "😩" ;;
      "wedding") echo -n "💒" ;;
      "weight_lifter") echo -n "🏋" ;;
      "whale") echo -n "🐋" ;;
      "wheelchair_manual") echo -n "🦽" ;;
      "wheelchair_motorized") echo -n "🦼" ;;
      "white_flag") echo -n "🏳" ;;
      "white_flower") echo -n "💮" ;;
      "white_hair") echo -n "🦳" ;;
      "white_heart") echo -n "🤍" ;;
      "white_latin_cross") echo -n "🕆" ;;
      "white_pennant") echo -n "🏱" ;;
      "white_rosette") echo -n "🏵" ;;
      "white_square_button") echo -n "🔳" ;;
      "white_sun_behind_cloud") echo -n "🌦" ;;
      "white_sun") echo -n "🌥" ;;
      "white_touch_telephone") echo -n "🕾" ;;
      "wilted_flower") echo -n "🥀" ;;
      "wind_blowing_face") echo -n "🌬" ;;
      "wind_chime") echo -n "🎐" ;;
      "wind") echo -n "💨" ;;
      "winking_face") echo -n "😉" ;;
      "wolf_face") echo -n "🐺" ;;
      "woman") echo -n "👩" ;;
      "womans_bots") echo -n "👢" ;;
      "womans_clothes") echo -n "👚" ;;
      "womans_hat") echo -n "👒" ;;
      "womans_sandal") echo -n "👡" ;;
      "women") echo -n "🚺" ;;
      "world_map") echo -n "🗺" ;;
      "worried_face") echo -n "😟" ;;
      "wrapped_present") echo -n "🎁" ;;
      "wrench") echo -n "🔧" ;;
      "wrestling") echo -n "🤼" ;;
      "x-ray") echo -n "🩻" ;;
      "yellow_heart") echo -n "💛" ;;
      "yo-yo") echo -n "🪀" ;;
      "zebra_face") echo -n "🦓" ;;
      "zombie") echo -n "🧟" ;;
      *) echo -n "" ;;   # if no match return nothing
   esac
} # -------------------- End of text_icon routine --------------------
