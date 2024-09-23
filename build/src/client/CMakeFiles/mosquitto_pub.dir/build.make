# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/gaiye/Projects/mqtt_over_quic

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/gaiye/Projects/mqtt_over_quic/build

# Include any dependencies generated for this target.
include src/client/CMakeFiles/mosquitto_pub.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/client/CMakeFiles/mosquitto_pub.dir/compiler_depend.make

# Include the progress variables for this target.
include src/client/CMakeFiles/mosquitto_pub.dir/progress.make

# Include the compile flags for this target's objects.
include src/client/CMakeFiles/mosquitto_pub.dir/flags.make

src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.o: src/client/CMakeFiles/mosquitto_pub.dir/flags.make
src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.o: /home/gaiye/Projects/mqtt_over_quic/src/client/pub_client.c
src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.o: src/client/CMakeFiles/mosquitto_pub.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/gaiye/Projects/mqtt_over_quic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.o"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.o -MF CMakeFiles/mosquitto_pub.dir/pub_client.c.o.d -o CMakeFiles/mosquitto_pub.dir/pub_client.c.o -c /home/gaiye/Projects/mqtt_over_quic/src/client/pub_client.c

src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/mosquitto_pub.dir/pub_client.c.i"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gaiye/Projects/mqtt_over_quic/src/client/pub_client.c > CMakeFiles/mosquitto_pub.dir/pub_client.c.i

src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/mosquitto_pub.dir/pub_client.c.s"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gaiye/Projects/mqtt_over_quic/src/client/pub_client.c -o CMakeFiles/mosquitto_pub.dir/pub_client.c.s

src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.o: src/client/CMakeFiles/mosquitto_pub.dir/flags.make
src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.o: /home/gaiye/Projects/mqtt_over_quic/src/client/pub_shared.c
src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.o: src/client/CMakeFiles/mosquitto_pub.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/gaiye/Projects/mqtt_over_quic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.o"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.o -MF CMakeFiles/mosquitto_pub.dir/pub_shared.c.o.d -o CMakeFiles/mosquitto_pub.dir/pub_shared.c.o -c /home/gaiye/Projects/mqtt_over_quic/src/client/pub_shared.c

src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/mosquitto_pub.dir/pub_shared.c.i"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gaiye/Projects/mqtt_over_quic/src/client/pub_shared.c > CMakeFiles/mosquitto_pub.dir/pub_shared.c.i

src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/mosquitto_pub.dir/pub_shared.c.s"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gaiye/Projects/mqtt_over_quic/src/client/pub_shared.c -o CMakeFiles/mosquitto_pub.dir/pub_shared.c.s

src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.o: src/client/CMakeFiles/mosquitto_pub.dir/flags.make
src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.o: /home/gaiye/Projects/mqtt_over_quic/src/client/client_shared.c
src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.o: src/client/CMakeFiles/mosquitto_pub.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/gaiye/Projects/mqtt_over_quic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.o"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.o -MF CMakeFiles/mosquitto_pub.dir/client_shared.c.o.d -o CMakeFiles/mosquitto_pub.dir/client_shared.c.o -c /home/gaiye/Projects/mqtt_over_quic/src/client/client_shared.c

src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/mosquitto_pub.dir/client_shared.c.i"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gaiye/Projects/mqtt_over_quic/src/client/client_shared.c > CMakeFiles/mosquitto_pub.dir/client_shared.c.i

src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/mosquitto_pub.dir/client_shared.c.s"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gaiye/Projects/mqtt_over_quic/src/client/client_shared.c -o CMakeFiles/mosquitto_pub.dir/client_shared.c.s

src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.o: src/client/CMakeFiles/mosquitto_pub.dir/flags.make
src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.o: /home/gaiye/Projects/mqtt_over_quic/src/client/client_props.c
src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.o: src/client/CMakeFiles/mosquitto_pub.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/gaiye/Projects/mqtt_over_quic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.o"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.o -MF CMakeFiles/mosquitto_pub.dir/client_props.c.o.d -o CMakeFiles/mosquitto_pub.dir/client_props.c.o -c /home/gaiye/Projects/mqtt_over_quic/src/client/client_props.c

src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/mosquitto_pub.dir/client_props.c.i"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/gaiye/Projects/mqtt_over_quic/src/client/client_props.c > CMakeFiles/mosquitto_pub.dir/client_props.c.i

src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/mosquitto_pub.dir/client_props.c.s"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/gaiye/Projects/mqtt_over_quic/src/client/client_props.c -o CMakeFiles/mosquitto_pub.dir/client_props.c.s

# Object files for target mosquitto_pub
mosquitto_pub_OBJECTS = \
"CMakeFiles/mosquitto_pub.dir/pub_client.c.o" \
"CMakeFiles/mosquitto_pub.dir/pub_shared.c.o" \
"CMakeFiles/mosquitto_pub.dir/client_shared.c.o" \
"CMakeFiles/mosquitto_pub.dir/client_props.c.o"

# External object files for target mosquitto_pub
mosquitto_pub_EXTERNAL_OBJECTS =

bin/x86_64chk/mosquitto_pub: src/client/CMakeFiles/mosquitto_pub.dir/pub_client.c.o
bin/x86_64chk/mosquitto_pub: src/client/CMakeFiles/mosquitto_pub.dir/pub_shared.c.o
bin/x86_64chk/mosquitto_pub: src/client/CMakeFiles/mosquitto_pub.dir/client_shared.c.o
bin/x86_64chk/mosquitto_pub: src/client/CMakeFiles/mosquitto_pub.dir/client_props.c.o
bin/x86_64chk/mosquitto_pub: src/client/CMakeFiles/mosquitto_pub.dir/build.make
bin/x86_64chk/mosquitto_pub: bin/x86_64chk/libmosquitto.so.2.0.18
bin/x86_64chk/mosquitto_pub: /usr/lib/x86_64-linux-gnu/libssl.so
bin/x86_64chk/mosquitto_pub: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/x86_64chk/mosquitto_pub: src/client/CMakeFiles/mosquitto_pub.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/gaiye/Projects/mqtt_over_quic/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable ../../bin/x86_64chk/mosquitto_pub"
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/mosquitto_pub.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/client/CMakeFiles/mosquitto_pub.dir/build: bin/x86_64chk/mosquitto_pub
.PHONY : src/client/CMakeFiles/mosquitto_pub.dir/build

src/client/CMakeFiles/mosquitto_pub.dir/clean:
	cd /home/gaiye/Projects/mqtt_over_quic/build/src/client && $(CMAKE_COMMAND) -P CMakeFiles/mosquitto_pub.dir/cmake_clean.cmake
.PHONY : src/client/CMakeFiles/mosquitto_pub.dir/clean

src/client/CMakeFiles/mosquitto_pub.dir/depend:
	cd /home/gaiye/Projects/mqtt_over_quic/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/gaiye/Projects/mqtt_over_quic /home/gaiye/Projects/mqtt_over_quic/src/client /home/gaiye/Projects/mqtt_over_quic/build /home/gaiye/Projects/mqtt_over_quic/build/src/client /home/gaiye/Projects/mqtt_over_quic/build/src/client/CMakeFiles/mosquitto_pub.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/client/CMakeFiles/mosquitto_pub.dir/depend

