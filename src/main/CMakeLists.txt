include_directories(
  ../lib/3rdparty
  ../lib/app
  ../lib/session
  ../lib/webengine
  ../lib/webtab
)
set(SRCS main.cpp)
if (WIN32)
    set(SRCS ${SRCS} version.rc)
    configure_file(veexversion.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/veexversion.h)
endif()
ecm_create_qm_loader(SRCS veex_qt)
add_executable(veex ${SRCS})

target_link_libraries(veex VeexPrivate)

if (APPLE)
    set_target_properties(veex PROPERTIES MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist)
    set_target_properties(veex PROPERTIES MACOSX_BUNDLE_GUI_IDENTIFIER "org.veex.VeexBrowser")
    set_target_properties(veex PROPERTIES MACOSX_BUNDLE_BUNDLE_NAME "Veex")
    install(FILES lib/data/icons/exeicons/veex.icns DESTINATION ${BUNDLE_INSTALL_DIR}/veex.app/Contents/Resources)
    #install(DIRECTORY ${CMAKE_BINARY_DIR}/bin/locale DESTINATION ${BUNDLE_INSTALL_DIR}/veex.app/Contents/Resources)
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/themes DESTINATION ${BUNDLE_INSTALL_DIR}/veex.app/Contents/Resources)
    install(DIRECTORY ${CMAKE_BINARY_DIR}/bin/plugins DESTINATION ${BUNDLE_INSTALL_DIR}/veex.app/Contents/Resources)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES FreeBSD OR CMAKE_SYSTEM_NAME MATCHES OpenBSD)
    target_link_libraries(veex execinfo)
endif()

if (UNIX AND NOT APPLE)
    install(TARGETS veex ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/themes DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/veex)
    if (KF6I18n_FOUND)
        ki18n_install(${CMAKE_SOURCE_DIR}/po)
    endif()
    ecm_install_po_files_as_qm(${CMAKE_SOURCE_DIR}/poqm)

    install(PROGRAMS ../../linux/applications/org.veex.VeexBrowser.desktop DESTINATION ${KDE_INSTALL_APPDIR})

    ecm_install_icons(ICONS
        ../../linux/hicolor/16-apps-veex.png
        ../../linux/hicolor/32-apps-veex.png
        ../../linux/hicolor/48-apps-veex.png
        ../../linux/hicolor/64-apps-veex.png
        ../../linux/hicolor/128-apps-veex.png
        ../../linux/hicolor/256-apps-veex.png
        ../../linux/hicolor/sc-apps-veex.svg
        DESTINATION ${KDE_INSTALL_ICONDIR} THEME hicolor)

    install(FILES ../../linux/completion/veex DESTINATION ${KDE_INSTALL_DATADIR}/bash-completion/completions)
    install(FILES ../../linux/appdata/org.veex.VeexBrowser.appdata.xml DESTINATION ${KDE_INSTALL_METAINFODIR})
elseif (WIN32)
    install(TARGETS veex ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/themes DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/veex)
    if (KF6I18n_FOUND)
        ki18n_install(${CMAKE_SOURCE_DIR}/po)
    endif()
    ecm_install_po_files_as_qm(${CMAKE_SOURCE_DIR}/poqm)

    ecm_install_icons(ICONS
        ../../linux/hicolor/16-apps-veex.png
        ../../linux/hicolor/32-apps-veex.png
        ../../linux/hicolor/48-apps-veex.png
        ../../linux/hicolor/64-apps-veex.png
        ../../linux/hicolor/128-apps-veex.png
        ../../linux/hicolor/256-apps-veex.png
        ../../linux/hicolor/sc-apps-veex.svg
        DESTINATION ${KDE_INSTALL_ICONDIR} THEME hicolor)
endif()
