cmake_minimum_required(VERSION 3.14)
set(CMAKE_C_STANDARD 11)

set(ENVSDK $ENV{PLAYDATE_SDK_PATH})

if (NOT ${ENVSDK} STREQUAL "")
	# Convert path from Windows
	file(TO_CMAKE_PATH ${ENVSDK} SDK)
else()
	execute_process(
			COMMAND bash -c "egrep '^\\s*SDKRoot' $HOME/.Playdate/config"
			COMMAND head -n 1
			COMMAND cut -c9-
			OUTPUT_VARIABLE SDK
			OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()

if (NOT EXISTS ${SDK})
	message(FATAL_ERROR "SDK Path not found; set ENV value PLAYDATE_SDK_PATH")
	return()
endif()

set(CMAKE_CONFIGURATION_TYPES "Debug;Release")
set(CMAKE_XCODE_GENERATE_SCHEME TRUE)

# Game Name Customization
set(PLAYDATE_GAME_NAME openbridge)
set(PLAYDATE_GAME_DEVICE openbridge_DEVICE)

project(${PLAYDATE_GAME_NAME} C ASM)

if (TOOLCHAIN STREQUAL "armgcc")
	add_executable(${PLAYDATE_GAME_DEVICE} src/pd_main.c ../proto/obsha256.c ../proto/obminijson.c ../proto/obproto.c)
	target_include_directories(${PLAYDATE_GAME_DEVICE} PRIVATE ../proto)
	# Newlib static refs only: this firmware never invokes syscalls at runtime
	# (integer-only snprintf, no file IO, no malloc).
	target_link_options(${PLAYDATE_GAME_DEVICE} PRIVATE --specs=nosys.specs)
else()
	add_library(${PLAYDATE_GAME_NAME} SHARED src/pd_main.c ../proto/obsha256.c ../proto/obminijson.c ../proto/obproto.c)
	target_include_directories(${PLAYDATE_GAME_NAME} PRIVATE ../proto)
endif()

include(${SDK}/C_API/buildsupport/playdate_game.cmake)
