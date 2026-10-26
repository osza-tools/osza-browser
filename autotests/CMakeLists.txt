include(ECMMarkAsTest)

set(osza_autotests_SRCS )

qt_add_resources(osza_autotests_SRCS autotests.qrc)

macro(osza_tests)
    foreach(_testname ${ARGN})
        add_executable(${_testname} ${_testname}.cpp ${_testname}.h ${osza_autotests_SRCS})
        target_link_libraries(${_testname} Qt::Test OszaPrivate)
        add_test(NAME osza-${_testname} COMMAND ${_testname})
        ecm_mark_as_test(${_testname})
        set_tests_properties(osza-${_testname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_testname)
endmacro()

osza_tests(
    qztoolstest
    cookiestest
    adblocktest
    updatertest
    locationbartest
    opensearchenginetest
    webviewtest
    webtabtest
    sqldatabasetest
)

if (BUILD_TESTING_ONLINE)
    osza_tests(
        sitesettingstest
    )
endif()

set(osza_autotests_SRCS ${CMAKE_SOURCE_DIR}/tests/modeltest/modeltest.cpp)
include_directories(${CMAKE_SOURCE_DIR}/tests/modeltest)
osza_tests(
    tabmodeltest
)

set(osza_autotests_SRCS passwordbackendtest.cpp)
include_directories(${OPENSSL_INCLUDE_DIR})
osza_tests(
    databasepasswordbackendtest
    databaseencryptedpasswordbackendtest
)

set(osza_autotests_SRCS
    qml/qmltestitem.cpp
    qml/qmltesthelper.cpp
)

macro(osza_qml_tests)
    foreach(_testname ${ARGN})
        add_executable(${_testname} qml/${_testname}.cpp ${osza_autotests_SRCS})
        target_link_libraries(${_testname} Qt::Test OszaPrivate)
        add_test(NAME osza-qml-${_testname} COMMAND ${_testname})
        ecm_mark_as_test(${_testname})
        set_tests_properties(osza-qml-${_testname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_testname)
endmacro()

osza_qml_tests(
    qmlbookmarksapitest
    qmltopsitesapitest
    qmlhistoryapitest
    qmlcookiesapitest
    qmlclipboardapitest
    qmltabsapitest
    qmlwindowsapitest
    qmluserscriptapitest
)
