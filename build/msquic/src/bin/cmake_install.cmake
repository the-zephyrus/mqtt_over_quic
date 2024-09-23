# Install script for directory: /home/gaiye/Projects/mqtt_over_quic/msquic/src/bin

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libmsquic.so.2.5.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libmsquic.so.2"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/gaiye/Projects/mqtt_over_quic/build/msquic/bin/Debug/libmsquic.so.2.5.0"
    "/home/gaiye/Projects/mqtt_over_quic/build/msquic/bin/Debug/libmsquic.so.2"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libmsquic.so.2.5.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libmsquic.so.2"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "::::::::::::::"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES "/home/gaiye/Projects/mqtt_over_quic/build/msquic/bin/Debug/libmsquic.so")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/gaiye/Projects/mqtt_over_quic/build/msquic/src/bin/CMakeFiles/msquic.dir/install-cxx-module-bmi-Debug.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquic.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquic.hpp"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquic_fuzz.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquic_posix.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquic_winkernel.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquic_winuser.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquichelper.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/msquicp.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_cert.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_crypt.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_datapath.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_driver_helpers.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_hashtable.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_pcp.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_platform.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_platform_posix.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_platform_winkernel.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_platform_winuser.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_sal_stub.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_storage.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_tls.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_toeplitz.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_trace.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_trace_manifested_etw.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_var_int.h"
    "/home/gaiye/Projects/mqtt_over_quic/msquic/src/bin/../inc/quic_versions.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/msquic" TYPE FILE FILES "/home/gaiye/Projects/mqtt_over_quic/build/msquic-config.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/msquic/msquic.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/msquic/msquic.cmake"
         "/home/gaiye/Projects/mqtt_over_quic/build/msquic/src/bin/CMakeFiles/Export/8748b72d3c8ce6f4827ac8b99deac313/msquic.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/msquic/msquic-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/msquic/msquic.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/msquic" TYPE FILE FILES "/home/gaiye/Projects/mqtt_over_quic/build/msquic/src/bin/CMakeFiles/Export/8748b72d3c8ce6f4827ac8b99deac313/msquic.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/msquic" TYPE FILE FILES "/home/gaiye/Projects/mqtt_over_quic/build/msquic/src/bin/CMakeFiles/Export/8748b72d3c8ce6f4827ac8b99deac313/msquic-debug.cmake")
  endif()
endif()

