#! /bin/sh
$EXTRACT_TR_STRINGS `find . -name '*.cpp' -o -name '*.h' -o -name '*.ui'` -o $podir/osza_flashcookiemanager_qt.pot
