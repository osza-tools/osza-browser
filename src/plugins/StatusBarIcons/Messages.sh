#! /bin/sh
$EXTRACT_TR_STRINGS `find . -name '*.cpp' -o -name '*.h' -o -name '*.ui'` -o $podir/osza_statusbaricons_qt.pot
