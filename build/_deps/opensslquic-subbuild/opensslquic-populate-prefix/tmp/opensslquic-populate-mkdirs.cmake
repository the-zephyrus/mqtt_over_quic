# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/gaiye/Projects/mqtt_over_quic/msquic/submodules"
  "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-build"
  "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix"
  "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix/tmp"
  "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix/src/opensslquic-populate-stamp"
  "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix/src"
  "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix/src/opensslquic-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix/src/opensslquic-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/gaiye/Projects/mqtt_over_quic/build/_deps/opensslquic-subbuild/opensslquic-populate-prefix/src/opensslquic-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
