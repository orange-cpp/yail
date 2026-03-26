# Installing yail

## Build and install

```bash
cmake --preset windows-release-vcpkg`
cmake --build cmake-build/build/windows-release-vcpkg` --target install
```

The default install prefix is `cmake-build/install/windows-release-vcpkg`. To change it, pass `-DCMAKE_INSTALL_PREFIX=/your/path` during configure.

## CMake integration

After installing, add yail to your project:

```cmake
find_package(yail CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE yail::yail)
```

If you installed to a non-standard prefix, point CMake to it:

```bash
cmake -DCMAKE_PREFIX_PATH=/your/install/path ..
```
