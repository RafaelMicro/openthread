# sdk_generate_component_tag()
sdk_generate_library(openthread_port)

sdk_add_include_directories(
    include
)
sdk_library_add_public_include_directories(include)
sdk_add_private_include_directories(include)

# Continuing the library-boundary rework (docs/internal/architecture/lib-dependencies.md).
# OpenThread ships its own include/openthread/cli.h, colliding by filename
# with the SDK's components/utility/cli/Inc/cli.h. ot_radio.c/ot_uart.c's
# #include "cli.h" means the SDK one (they use sh_cmd_t/cb_shell_out_t, SDK
# shell types) -- whichever -I comes first on the compile line wins the
# search. CMake always places a target's own direct target_include_directories
# entries before anything propagated via target_link_libraries, regardless of
# call order -- so reordering sdk_library_depends_on(cli) alone doesn't help;
# this needs its own direct (private) declaration, ahead of the bare
# OpenThread paths below, to win the search. (Previously accidental: whichever
# directory CMake happened to process first in the global pool decided this;
# now explicit and pinned.)
if(CONFIG_BUILD_COMPONENT_CLI)
    sdk_add_private_include_directories(${CMAKE_SOURCE_DIR}/components/utility/cli/Inc)
endif()

if(CONFIG_FREERTOS)
    sdk_library_depends_on(sdk::freertos)
endif()
sdk_library_depends_on(sdk::soc_driver sdk::hosal log lmac15p4 utility)
if(CONFIG_BUILD_COMPONENT_ENHANCED_FLASH_DATASET)
    sdk_library_depends_on(EnhancedFlashDataset)
endif()
if(CONFIG_BUILD_COMPONENT_CLI)
    sdk_library_depends_on(cli)
endif()
if(CONFIG_OT_RCP_EZMESH AND CONFIG_BUILD_COMPONENT_CPC)
    sdk_library_depends_on(cpc)
endif()

# OpenThread's own include paths are published bare/unowned by
# components/network/thread/CMakeLists.txt (same pattern as CMSIS Core for
# cmsis_dsp) -- no real CMake target to depend on, so declared directly.
sdk_add_private_include_directories(
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/include/openthread
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/include/openthread/platform
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/src/core
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/src/core/config
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/src
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/src/include
    ${CMAKE_SOURCE_DIR}/components/network/thread/openthread/examples/config
)

if((${CONFIG_CHIP} STREQUAL "RT584S") OR (${CONFIG_CHIP} STREQUAL "RT584H") OR (${CONFIG_CHIP} STREQUAL "RT584L"))
sdk_add_include_directories(
    ${CMAKE_SOURCE_DIR}/components/platform/hosal/hosal_rt584/Inc
)
elseif((${CONFIG_CHIP} STREQUAL "RT581") OR (${CONFIG_CHIP} STREQUAL "RT582") OR (${CONFIG_CHIP} STREQUAL "RT583"))
sdk_add_include_directories(
    ${CMAKE_SOURCE_DIR}/components/platform/hosal/hosal_rt582/Inc
)
endif()

sdk_library_add_sources(
    src/ot_alarm.c
    src/ot_crypto.c
    src/ot_diag.c
    src/ot_entropy.c
    src/ot_freertos.c
    src/ot_logging.c
    src/ot_misc.c
    src/ot_radio.c
    src/ot_settings.c
    utils/mac_frame.cpp    
    utils/mac_frame_gen.c    
    utils/soft_source_match_table.c
    crypto/aes_alt.c
    crypto/ecjpake_alt.c
    crypto/sha256_alt.c
)

if(CONFIG_OT_RCP_EZMESH)
    sdk_library_add_sources(ncp/ncp.c)
    sdk_library_add_sources(ncp/ncp_cpc.cpp)
    sdk_library_add_sources(src/ot_uart.c)
else()
    sdk_library_add_sources(src/ot_uart.c)
endif()

sdk_library_strict_includes()