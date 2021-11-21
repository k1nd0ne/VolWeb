# Volweb 

Creator : Félix Guyard

Twitter : @k1nd0ne

The goal volweb is to improve the effeciency of memory forensics by providing a centralized, visual and enhance memory analysis plateform for incident responder and digital forensics investigators.

Volweb is based on volatility3, and this plateform will evolve with the framework developpement.

**Volweb is still in Alpha version and will evolve quickly.** 
Communications of updates will be via twitter.

## Features
The platform is currently supporting the following features : 

- Investigation creation and dump upload
- IoC import
- IoC extraction with linked process
- process tree
- process scan
- process dump
- process env
- process cmdline
- process privileges
- network scan
- hashdump
- dlllist
- filescan
- Timeline Explorer
- User Authentication
- User Management


## Deploy
Volweb is fully dockerized and ready to be deployed on a production server. 
In order to deploy Volweb, you will need to follow these steps : 

Clone the repository. 

```
git clone $project-link$
```

Then, edit the **docker/volweb.env** file and add the secret informations according to your need to the following fields: 

```
 POSTGRES_USER=USER_HERE
 POSTGRES_PASSWORD=PASSWORD_HERE
 DJANGO_SECRET=SECRET_KEY_HERE
```

Next, add your ssl certificate into the **nginx/ssl** folder (generated via certbot for example).

```
cp fullchain.pem privkey.pem ./volweb-cert/docker/nginx/ssl
```

Build the docker and run it.

```
docker-compose build
docker-compose up -d
```

Create a superuser account : 

```
docker exec -it $(docker ps -aqf "name=django") python manage.py createsuperuser
```

The ngnix logs can be found in the **/ngnix/log** folder.

## Reset 

/!\ This procedure will delete all the memory dump and database items and reset the volweb platform /!\

```
docker-compose down --rmi all --volumes
```

```
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc"  -delete
```

## Wiki

A quick guide is available in the project wiki to configure the Volweb platform.

# TODO
- Mac OS support
- Linux support
- Visual confirmation of what to not look (legit process highlight integration)
- Import multiple IOC from a CSV
