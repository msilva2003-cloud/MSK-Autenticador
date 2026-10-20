cmake_minimum_required(VERSION 3.24)
project(MSKAuthenticator VERSION 0.1.4 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(FetchContent)
set(ZXING_READERS ON CACHE BOOL "" FORCE)
set(ZXING_WRITERS ON CACHE BOOL "" FORCE)
set(ZXING_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZXING_TESTS OFF CACHE BOOL "" FORCE)
set(ZXING_PYTHON_MODULE OFF CACHE BOOL "" FORCE)
set(ZXING_C_API OFF CACHE BOOL "" FORCE)
FetchContent_Declare(zxing
  GIT_REPOSITORY https://github.com/zxing-cpp/zxing-cpp.git
  GIT_TAG 287c85df6f961c8efbfb5ffd736cd9457b8b890e
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(zxing)

configure_file(src/app.rc.in "${CMAKE_CURRENT_BINARY_DIR}/app.rc" @ONLY)

add_executable(MSKAuthenticator WIN32
  "${CMAKE_CURRENT_BINARY_DIR}/app.rc"
  src/main.cpp
  src/authenticator.cpp
  src/authenticator.h
  src/update.cpp
  src/update.h
  src/qr_export.cpp
  src/qr_export.h
  src/camera.cpp
  src/camera.h)
target_compile_definitions(MSKAuthenticator PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(MSKAuthenticator PRIVATE /W4 /permissive- /sdl /guard:cf /utf-8)
target_link_options(MSKAuthenticator PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /GUARD:CF)
target_link_libraries(MSKAuthenticator PRIVATE ZXing::ZXing
  bcrypt crypt32 windowscodecs ole32 comdlg32 shell32 gdiplus dwmapi winhttp mf mfplat mfreadwrite mfuuid)
