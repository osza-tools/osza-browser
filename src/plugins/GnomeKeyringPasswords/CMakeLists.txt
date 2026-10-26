add_definitions(${GNOME_KEYRING_CFLAGS} ${GNOME_KEYRING_CFLAGS_OTHER})

set( GnomeKeyringPasswords_SRCS
	gnomekeyringplugin.cpp
	gnomekeyringpasswordbackend.cpp
	)

ecm_create_qm_loader( GnomeKeyringPasswords_SRCS osza_gnomekeyringpasswords_qt )

add_library(GnomeKeyringPasswords MODULE ${GnomeKeyringPasswords_SRCS} ${RSCS})
install(TARGETS GnomeKeyringPasswords DESTINATION ${OSZA_INSTALL_PLUGINDIR})
target_link_libraries(GnomeKeyringPasswords PkgConfig::GNOME_KEYRING OszaPrivate)

