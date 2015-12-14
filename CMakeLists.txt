#
# Copyright (c) 2015 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)
SET(CMAKE_SKIP_BUILD_RPATH true)

PROJECT(pkgmgr-tool C)

SET(VERSION 0.1.0)
SET(VERSION_MAJOR 0)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR ${LIB_INSTALL_DIR})
SET(INCLUDEDIR "\${prefix}/include")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/client/include)

INCLUDE(FindPkgConfig)

pkg_check_modules(pkgs_initdb REQUIRED libsmack libxml-2.0 bundle pkgmgr-parser pkgmgr-info libtzplatform-config pkgmgr)
FOREACH(flag ${pkgs_initdb_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(pkgs_test REQUIRED dlog glib-2.0 libxml-2.0 bundle pkgmgr-parser pkgmgr-info libtzplatform-config security-manager pkgmgr capi-security-privilege-manager)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs -pie" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIE")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -fPIE")
SET(CMAKE_C_FLAGS_RELEASE "-O2 -fPIE")

ADD_EXECUTABLE(pkgcmd src/pkg_cmd.c src/delta.c)
TARGET_LINK_LIBRARIES(pkgcmd pkgmgr-client ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkgcmd DESTINATION bin)

ADD_EXECUTABLE(pkginfo src/pkg_info.c)
TARGET_LINK_LIBRARIES(pkginfo pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkginfo DESTINATION bin)

ADD_EXECUTABLE(pkg_privilege src/pkg_privilege.c)
TARGET_LINK_LIBRARIES(pkg_privilege ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_privilege DESTINATION bin)

ADD_EXECUTABLE(pkg_install_ug src/pkg_install_ug.c)
TARGET_LINK_LIBRARIES(pkg_install_ug ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_install_ug DESTINATION bin)

ADD_EXECUTABLE(pkg_getsize src/pkg_getsize.c)
TARGET_LINK_LIBRARIES(pkg_getsize pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_getsize DESTINATION bin)

ADD_EXECUTABLE(pkg_clearcache src/pkg_clearcache.c)
TARGET_LINK_LIBRARIES(pkg_clearcache ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_clearcache DESTINATION bin)

ADD_EXECUTABLE(pkg_initdb src/pkg_initdb.c)
TARGET_LINK_LIBRARIES(pkg_initdb ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_initdb DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/10_package-manager-add.post  DESTINATION ${SYSCONF_INSTALL_DIR}/gumd/useradd.d/)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/mime.wac.xml DESTINATION /usr/share/mime/packages/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/mime.tpk.xml DESTINATION /usr/share/mime/packages/)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/pkgmgr.patch.sh.in pkgmgr.patch.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr.patch.sh DESTINATION ${SYSCONF_INSTALL_DIR}/opt/upgrade/)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/pkgmgr-unzip-tpk.sh.in pkgmgr-unzip-tpk.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr-unzip-tpk.sh DESTINATION ${SYSCONF_INSTALL_DIR}/package-manager/)
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/data/pkgmgr-create-delta.sh.in pkgmgr-create-delta.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr-create-delta.sh DESTINATION ${SYSCONF_INSTALL_DIR}/package-manager/)
