# README #

### What is this repository for? ###

* Web service that allows to store password on file system encrypted
* 1.0

### Dependencies
* docker-compose
* docker
### How do I get set up? ###

* Clone the repo and launch docker-compose up -d. It will start a web service listening on 5000 port
* Add the file config.py in the root directory and add access password(access_pwd="PASSWORD") for basic authentication. User is service_keystore
* Set the crypto key calling set_keyfile endpoint (see below)
* If you don't specify field host in json payload, server will get hostname from where the request comes from
* Every endpoints are wrapped with basic authentication protocol
  
REST endpoints:

  - set_password
    - method: POST
    - payload: json
    - fields: username,password,host(not mandatory)
 
  - get_password
    - method: POST
    - payload: json
    - fields: username,host(not mandatory)
 
  - update_password
    - method: POST
    - payload: json
    - fields: username,password,host(not mandatory)
 
  - delete_password
    - method: POST
    - payload: json
    - fields: username,host(not mandatory)
  
  - set_keyfile
    - method: POST
    - padyload: json
    - fields: host(not mandatory)
  
Every endpoints return a json payload with two fields:
  - success: ok or ko
  - message: error or info message 

### Examples
set_keyfile:
```
curl --location --request POST 'localhost:5000/set_keyfile' \                        
--header 'Authorization: Basic c2VydmljZV9rZXlzdG9yZTo0azhwUS11STZtYkMwdFZLN2Y=' \
--header 'Content-Type: application/json' \
--data-raw '{
    "host":"localhost"
}'
```

set_password:
```
curl --location --request POST 'localhost:5000/set_password' \
--header 'Authorization: Basic c2VydmljZV9rZXlzdG9yZTo0azhwUS11STZtYkMwdFZLN2Y=' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username": "pippo",
    "password": "#z:RWx+nGN_7mkG"
}'
```

get_password:
```
curl --location --request POST 'localhost:5000/get_password' \
--header 'Authorization: Basic c2VydmljZV9rZXlzdG9yZTo0azhwUS11STZtYkMwdFZLN2Y=' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username": "pippo"
}'
```

update_password:
```
curl --location --request POST 'localhost:5000/update_password' \
--header 'Authorization: Basic c2VydmljZV9rZXlzdG9yZTo0azhwUS11STZtYkMwdFZLN2Y=' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username":"pippo",
    "password": "asdad324234234^"
}'
```

delete_password:
```
curl --location --request POST 'localhost:5000/delete_password' \
--header 'Authorization: Basic c2VydmljZV9rZXlzdG9yZTo0azhwUS11STZtYkMwdFZLN2Y=' \
--header 'Content-Type: application/json' \
--data-raw '{
    "username":"pippo"
}'
```
