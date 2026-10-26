set( TestPlugin_SRCS
	testplugin.cpp
	testplugin_sidebar.cpp
        testplugin.h
        testplugin_sidebar.h
        )

ecm_create_qm_loader( TestPlugin_SRCS osza_testplugin_qt )

add_library(TestPlugin MODULE ${TestPlugin_SRCS} ${RSCS})
install(TARGETS TestPlugin DESTINATION ${OSZA_INSTALL_PLUGINDIR})
target_link_libraries(TestPlugin OszaPrivate)
