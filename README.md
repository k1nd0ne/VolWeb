![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/title.png)

Volweb is a digtial forensic memory analysis platform. The goal of VolWeb is to improve the efficiency of memory forensics by providing a centralized, visual and enhanced platform for incident responders and digital forensics investigators.
VolWeb is based on volatility3, and this platform will evolve with the framework development.

![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/investigation.png)


**Volweb is still in Beta version and will evolve quickly.** 
The updates communications will be on twitter or by following the github.

## Features ✅
The platform is currently supporting the following features: 

- Investigation creation and dump upload
- IoC import
- IoC extraction with linked processes
- process tree
- process scan
- process dump
- process env
- process cmdline
- process privileges
- process dump
- network scan
- hashdump
- dlllist
- filescan
- Timeline Explorer
- malfind
- User Authentication
- User Management
- Automatic Report Generation


## Getting Started 🛠️
Volweb is fully dockerized and can be deployed in a production environement. 
In order to deploy Volweb, you should follow these steps: 

Clone the repository. 

```
git clone https://github.com/k1nd0ne/VolWeb
```

Then, edit the **docker/volweb.env** file and add the secret information according to your need to the following fields: 

```
 POSTGRES_USER=USER_HERE
 POSTGRES_PASSWORD=PASSWORD_HERE
 DJANGO_SECRET=SECRET_KEY_HERE
```

Next, add your ssl certificate into the **nginx/ssl** folder (generated via certbot or openssl for example).

```
cp fullchain.pem privkey.pem ./volweb-cert/docker/nginx/ssl
```

Build the docker and run it.

```
docker-compose build
docker-compose up -d
```

Create a superuser account: 

```
docker exec -it $(docker ps -aqf "name=django") python manage.py createsuperuser
```

The ngnix logs can be found in the **/ngnix/log** folder.

## Reset

/!\ This procedure will delete all the memory dump and database items and reset the volweb platform /!\

```
cd VolWeb/docker
docker-compose down --rmi all --volumes
```

```
cd VolWeb
find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc"  -delete
```

## Important Note

To be able to see the forensic investigator's name when creating a new analysis, you’ll need to fill in the "First Name" and "Last Name "fields in the User section of the Django administration panel -> https://[IP]/admin.

![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/Note.png)

## Issues ⚠️
If you have found an issue, please raise it. 
I am performing 1 sprint every month to fix discovered bugs.

### Need to contact me? 
Contact me at k1nd0ne@mail.com for any questions regarding this tool.

# Next Release goals 
- Admin account creation at first launch
- Celery Task timeout in case of corrupted memory dump

# Global goals
- Code optimisation
- Docker optimisation
- Add missing modules to the windows memory analysis.
- Mac OS support
- Linux support
- Visual confirmation of what to not look (legit process highlight integration)
- Import multiple IOC from a CSV
- Export IOCs to a CSV for qualification and integration to Threat Intelligence Platforms
