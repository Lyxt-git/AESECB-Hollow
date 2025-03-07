cmake_minimum_required(VERSION 3.29)
project(Obfuscation_Project_Host_using_C__)

set(CMAKE_CXX_STANDARD 14)

# Set Crypto++ paths (update the paths to match your setup)
set(CRYPTOPP_ROOT "C:/cryptopp/build")   # Use the build directory where libcryptlib.a exists
set(CRYPTOPP_INCLUDE_DIR "C:/cryptopp/") # Include path
set(CRYPTOPP_LIBRARY "${CRYPTOPP_ROOT}/libcryptlib.a")  # Path to the static library

# Include Crypto++ headers
include_directories(${CRYPTOPP_INCLUDE_DIR})
link_directories(${CRYPTOPP_ROOT})

# Define executable
add_executable(Obfuscation_Project_Host_using_C__ "Hollow C++.cpp"
        "Hollow C++.cpp")

# Link Crypto++ library
target_link_libraries(Obfuscation_Project_Host_using_C__ ${CRYPTOPP_LIBRARY})
