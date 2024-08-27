# GameServer
This is the repository containing all source files needed to build and containerize game server infrastructure not including the game server (instance of the game) itself.  
  
This repository is using and requires:
- CMake
- C++17
- Protobuf
- OpenSSL at least in version 3.2 (Argon2 was added in this version)
- Clang
- Docker

## Usage

All source files are included in ``src`` and ``include`` directories. ``docker`` folder contains required docker files and usage manual for docker. ``lib`` and ``external`` folders are empty, as CMake uses find_package() that looks for libraries installed in OS.

### Building
While in main directory:  
```console
cmake -B build
cmake --build Build
```
  
Built binaries are saved under path ``build/src/<module_name>/<module_name>``, where available modules are:
- broker
- auth_server