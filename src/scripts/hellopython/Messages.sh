#! /bin/sh

XGETTEXT_FLAGS_PYTHON="\
--copyright-holder=This_file_is_part_of_Osza \
--msgid-bugs-address=https://github.com/osza-tools/osza-browser/issues \
--from-code=UTF-8 \
-L Python \
-ki18n:1 -ki18np:1,2 \
"

$XGETTEXT_PROGRAM $XGETTEXT_FLAGS_PYTHON `find . -name '*.py'` -o $podir/osza_hellopython.pot
