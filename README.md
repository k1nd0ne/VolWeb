
![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/title.png)

Volweb is a digtial  forensic memory analysis plateforme. The goal volweb is to improve the effeciency of memory forensics by providing a centralized, visual and enhance plateform for incident responder and digital forensics investigators.
Volweb is based on volatility3, and this plateform will evolve with the framework developpement.

**Volweb is still in Beta version and will evolve quickly.** 
Communications of updates will be via twitter and by following the release on github.

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
- process dump
- network scan
- hashdump
- dlllist
- filescan
- Timeline Explorer
- User Authentication
- User Management
- Automatic Report Generation


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

## Important Note

To be able to see forensic investigators name, you need to fill the First Name and Last name in the User section in the django administration panel.

![alt text](https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/Note.png)

### Issues
I you have found an issue, please raise it. 
I'm doing 1 sprint every month to fix discovered bugs.

### Need to contact me ? 
Contact me at k1nd0ne@mail.com for any questions regarding this tool.

# Next Release goals 
- Integrate Volatility results directly inside the database (Currently in JSON).
- Better file & process dump management (integration with celery)
- Add missing module for the windows memory analysis.
- Fix various discovered bugs.

# Global goals
- Mac OS support
- Linux support
- Visual confirmation of what to not look (legit process highlight integration)
- Import multiple IOC from a CSV
- Export IOCs to a CSV for qualification and integration to Threat Intelligence Plateforms
