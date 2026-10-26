set( SiteSettingsView_SRCS
        sitesettingsview_controller.cpp
        sitesettingsview_plugin.cpp
        sitesettingsview_widget.cpp
        sitesettingsview_controller.h
        sitesettingsview_plugin.h
        sitesettingsview_widget.h
)

ecm_create_qm_loader( SiteSettingsView_SRCS osza_sitesettingsview_qt )

add_library(SiteSettingsView MODULE ${SiteSettingsView_SRCS} ${RSCS})
install(TARGETS SiteSettingsView DESTINATION ${OSZA_INSTALL_PLUGINDIR})
target_link_libraries(SiteSettingsView OszaPrivate)
