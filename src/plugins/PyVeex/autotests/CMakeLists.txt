macro(pyveex_tests)
    foreach(_testname ${ARGN})
        add_test(NAME pyveex-${_testname} COMMAND pyveextestrunner ${CMAKE_CURRENT_SOURCE_DIR}/${_testname}.py)
        set_tests_properties(pyveex-${_testname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_testname)
endmacro()

add_executable(pyveextestrunner pyveextestrunner.cpp)
target_link_libraries(pyveextestrunner VeexPrivate Qt6::Test)

pyveex_tests(
    basictest
)
