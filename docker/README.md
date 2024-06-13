``docker pull mongo``  
``docker network create -d bridge --subnet 172.18.0.0/24 auth_server_network``  
``docker network create -d bridge --subnet 172.18.1.0/24 game_server_network``  
``docker network create -d bridge --subnet 172.18.2.0/24 database_network``  
``docker volume create game_server_database``  
Place the file containing root password in /run/secrets/mongodb_root_pwd and secure the directory  
``docker run -d -p 27017:27017 --network database_network --name mongodb -v game_server_database:/data/db -e MONGODB_INITDB_ROOT_USERNAME=game_server_root_user -e MONGODB_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongodb_root_pwd mongo:latest``  
