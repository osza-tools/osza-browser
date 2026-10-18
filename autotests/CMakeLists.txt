include(ECMMarkAsTest)

set(veex_autotests_SRCS )

qt_add_resources(veex_autotests_SRCS autotests.qrc)

macro(veex_tests)
    foreach(_testname ${ARGN})
        add_executable(${_testname} ${_testname}.cpp ${_testname}.h ${veex_autotests_SRCS})
        target_link_libraries(${_testname} Qt::Test VeexPrivate)
        add_test(NAME veex-${_testname} COMMAND ${_testname})
        ecm_mark_as_test(${_testname})
        set_tests_properties(veex-${_testname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_testname)
endmacro()

veex_tests(
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
    veex_tests(
        sitesettingstest
    )
endif()

set(veex_autotests_SRCS ${CMAKE_SOURCE_DIR}/tests/modeltest/modeltest.cpp)
include_directories(${CMAKE_SOURCE_DIR}/tests/modeltest)
veex_tests(
    tabmodeltest
)

set(veex_autotests_SRCS passwordbackendtest.cpp)
include_directories(${OPENSSL_INCLUDE_DIR})
veex_tests(
    databasepasswordbackendtest
    databaseencryptedpasswordbackendtest
)

set(veex_autotests_SRCS
    qml/qmltestitem.cpp
    qml/qmltesthelper.cpp
)

macro(veex_qml_tests)
    foreach(_testname ${ARGN})
        add_executable(${_testname} qml/${_testname}.cpp ${veex_autotests_SRCS})
        target_link_libraries(${_testname} Qt::Test VeexPrivate)
        add_test(NAME veex-qml-${_testname} COMMAND ${_testname})
        ecm_mark_as_test(${_testname})
        set_tests_properties(veex-qml-${_testname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_testname)
endmacro()

veex_qml_tests(
    qmlbookmarksapitest
    qmltopsitesapitest
    qmlhistoryapitest
    qmlcookiesapitest
    qmlclipboardapitest
    qmltabsapitest
    qmlwindowsapitest
    qmluserscriptapitest
)
