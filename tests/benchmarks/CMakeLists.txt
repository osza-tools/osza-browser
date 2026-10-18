set(veex_benchmarks_SRCS )

qt_add_resources(veex_benchmarks_SRCS benchmarks.qrc)

macro(veex_benchmarks)
    foreach(_benchmarkname ${ARGN})
        add_executable(${_benchmarkname} ${_benchmarkname}.cpp ${veex_benchmarks_SRCS})
        target_link_libraries(${_benchmarkname} Qt::Test VeexPrivate)
        #add_test(NAME veex-${_benchmarkname} COMMAND ${_benchmarkname})
        #ecm_mark_as_test(${_benchmarkname})
        #set_tests_properties(veex-${_benchmarkname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_benchmarkname)
endmacro()

veex_benchmarks(
    #adblockmatchrule
    adblockparserule
)
