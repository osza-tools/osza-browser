set(osza_benchmarks_SRCS )

qt_add_resources(osza_benchmarks_SRCS benchmarks.qrc)

macro(osza_benchmarks)
    foreach(_benchmarkname ${ARGN})
        add_executable(${_benchmarkname} ${_benchmarkname}.cpp ${osza_benchmarks_SRCS})
        target_link_libraries(${_benchmarkname} Qt::Test OszaPrivate)
        #add_test(NAME osza-${_benchmarkname} COMMAND ${_benchmarkname})
        #ecm_mark_as_test(${_benchmarkname})
        #set_tests_properties(osza-${_benchmarkname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_benchmarkname)
endmacro()

osza_benchmarks(
    #adblockmatchrule
    adblockparserule
)
