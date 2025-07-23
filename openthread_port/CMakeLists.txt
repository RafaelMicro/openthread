# sdk_generate_component_tag()
sdk_generate_library(openthread_port)

sdk_add_include_directories(
    include
)

if((${CONFIG_CHIP} STREQUAL "RT584S") OR (${CONFIG_CHIP} STREQUAL "RT584H") OR (${CONFIG_CHIP} STREQUAL "RT584L"))
sdk_add_include_directories(
    ${CMAKE_SOURCE_DIR}/componenets/platform/hosal/hosal_rt584/Inc
)
elseif((${CONFIG_CHIP} STREQUAL "RT581") OR (${CONFIG_CHIP} STREQUAL "RT582") OR (${CONFIG_CHIP} STREQUAL "RT583"))
sdk_add_include_directories(
    ${CMAKE_SOURCE_DIR}/componenets/platform/hosal/hosal_rt582/Inc
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