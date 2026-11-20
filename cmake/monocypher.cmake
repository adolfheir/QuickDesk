include(FetchContent)

# Monocypher 4.0.3, pinned to the release commit and archive checksum.
FetchContent_Declare(monocypher
    URL https://codeload.github.com/LoupVaillant/Monocypher/tar.gz/ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f
    URL_HASH SHA256=60dda1114a817826a0c753275190968e1b4a2d9f7e31e3d6daa09272c4746f5f
    SOURCE_SUBDIR unused
)
FetchContent_MakeAvailable(monocypher)

add_library(qd_monocypher STATIC ${monocypher_SOURCE_DIR}/src/monocypher.c)
target_include_directories(qd_monocypher SYSTEM PUBLIC ${monocypher_SOURCE_DIR}/src)
set_target_properties(qd_monocypher PROPERTIES
    AUTOMOC OFF AUTOUIC OFF AUTORCC OFF
    C_STANDARD 99 C_STANDARD_REQUIRED ON
)
