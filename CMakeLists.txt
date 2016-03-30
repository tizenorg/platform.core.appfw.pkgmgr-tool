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

pkg_check_modules(pkgs_initdb REQUIRED bundle pkgmgr-parser pkgmgr-info libtzplatform-config pkgmgr)
FOREACH(flag ${pkgs_initdb_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(pkgs_test REQUIRED dlog glib-2.0 bundle pkgmgr pkgmgr-parser pkgmgr-info pkgmgr-installer libtzplatform-config)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs -pie" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall -Werror")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIE")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -fPIE")
SET(CMAKE_C_FLAGS_RELEASE "-O2 -fPIE")

ADD_EXECUTABLE(pkgcmd src/pkg_cmd.c src/delta.c)
TARGET_LINK_LIBRARIES(pkgcmd ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkgcmd DESTINATION bin)

ADD_EXECUTABLE(pkginfo src/pkg_info.c)
TARGET_LINK_LIBRARIES(pkginfo ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkginfo DESTINATION bin)

ADD_EXECUTABLE(pkg_getsize src/pkg_getsize.c)
TARGET_LINK_LIBRARIES(pkg_getsize ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_getsize DESTINATION bin)

ADD_EXECUTABLE(pkg_clearcache src/pkg_clearcache.c)
TARGET_LINK_LIBRARIES(pkg_clearcache ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_clearcache DESTINATION bin)

ADD_EXECUTABLE(install_preload_tpk src/install_preload_tpk.c)
TARGET_LINK_LIBRARIES(install_preload_tpk ${pkgs_test_LDFLAGS})
INSTALL(TARGETS install_preload_tpk DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/10_package-manager-add.post  DESTINATION ${SYSCONF_INSTALL_DIR}/gumd/useradd.d/)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/mime.wac.xml DESTINATION /usr/share/mime/packages/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/data/mime.tpk.xml DESTINATION /usr/share/mime/packages/)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/pkgmgr.patch.sh.in pkgmgr.patch.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr.patch.sh DESTINATION ${SYSCONF_INSTALL_DIR}/opt/upgrade/)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/pkgmgr-unzip-pkg.sh.in pkgmgr-unzip-pkg.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr-unzip-pkg.sh DESTINATION ${SYSCONF_INSTALL_DIR}/package-manager/)
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/data/pkgmgr-create-delta.sh.in pkgmgr-create-delta.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr-create-delta.sh DESTINATION ${SYSCONF_INSTALL_DIR}/package-manager/)
