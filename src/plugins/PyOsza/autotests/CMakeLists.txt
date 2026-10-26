macro(pyosza_tests)
    foreach(_testname ${ARGN})
        add_test(NAME pyosza-${_testname} COMMAND pyoszatestrunner ${CMAKE_CURRENT_SOURCE_DIR}/${_testname}.py)
        set_tests_properties(pyosza-${_testname} PROPERTIES RUN_SERIAL TRUE)
    endforeach(_testname)
endmacro()

add_executable(pyoszatestrunner pyoszatestrunner.cpp)
target_link_libraries(pyoszatestrunner OszaPrivate Qt6::Test)

pyosza_tests(
    basictest
)
