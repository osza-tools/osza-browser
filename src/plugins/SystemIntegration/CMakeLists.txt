set(SystemIntegration_SRCS
    systemintegrationplugin.cpp
    kwalletpasswordbackend.cpp
    kioschemehandler.cpp
    downloadkjob.cpp
    systemintegrationplugin.h
    kwalletpasswordbackend.h
    kioschemehandler.h
    downloadkjob.h
)

ecm_create_qm_loader(SystemIntegration_SRCS veex_systemintegration_qt)

set(SystemIntegration_RSCS
    systemintegration.qrc
)
qt_add_resources(RSCS ${SystemIntegration_RSCS})

add_library(SystemIntegration MODULE ${SystemIntegration_SRCS} ${RSCS})
install(TARGETS SystemIntegration DESTINATION ${VEEX_INSTALL_PLUGINDIR})
target_link_libraries(SystemIntegration
    VeexPrivate
    KF6::Wallet
    KF6::KIOCore
    KF6::KIOWidgets
    KF6::Crash
    KF6::CoreAddons
    KF6::PurposeWidgets
    KF6::JobWidgets
)
