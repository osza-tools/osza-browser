#! /bin/sh

XGETTEXT_FLAGS_QML="\
--copyright-holder=This_file_is_part_of_Osza \
--msgid-bugs-address=https://github.com/osza-tools/osza-browser/issues \
--from-code=UTF-8 \
-L javascript \
-ki18n:1 -ki18np:1,2 \
"

$XGETTEXT_PROGRAM $XGETTEXT_FLAGS_QML `find . -name '*.qml' -o -name '*.js'` -o $podir/osza_helloqml.pot
