# Docker usage

## Additional Required files
``lib`` folder should be propagated with dynamic libraries required for this project:
- ``libcrypto.so.3`` - part of OpenSSL library, at least in version 3.2
- ``lissl.so.3`` - as above
- ``libprotobuf.so.xx`` - in the same version that the program was compiled with
  
Additionally, you should add correct binaries of modules in their corresponding folders under paths:
- ``auth_server/auth_server``
- ``broker/broker``
  
**It is also necessary to add cert files in certs folders of both ``broker`` and ``auth_server`` modules, as described in ``README.md`` files contained in certs folders**

## Building
Build all docker images from this root directory as paths in Dockerfile are relative to this folder.  
  
### Example build command:
``docker build -t <module_name> -f <module_name>/Dockerfile .``

# Docker run commands
```bash
docker pull mongo
docker network create -d bridge --subnet 172.18.0.0/24 auth_server_network 
docker network create -d bridge --subnet 172.18.1.0/24 game_server_network
docker network create -d bridge --subnet 172.18.2.0/24 database_network
docker volume create game_server_database  
```
Place the file containing root password in /run/secrets/mongodb_root_pwd and secure the directory. **It is definitely unsafe in production, as it should use an external vault for password storage.**
```bash
docker run -d -p 27017:27017 --network database_network --name mongodb -v game_server_database:/data/db -e MONGODB_INITDB_ROOT_USERNAME=game_server_root_user -e MONGODB_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongodb_root_pwd mongo:latest
docker run -d --name broker -p 4720:4720/udp broker:latest
docker network connect auth_server_network broker
docker network connect game_server_network broker
docker run -d --name auth_server --network auth_server_network auth_server:latest
docker network connect database_network auth_server
```

