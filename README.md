# GameServer

## Building

```sh
#while in home repo directory:

#remake make files
cmake .

#rebuild project
cmake --build build

#to run a project as test
cd src
../build/src/mock_server 4720
../build/src/mock_client localhost 4720
```