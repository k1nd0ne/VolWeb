<p align="center">
<img src="https://github.com/k1nd0ne/VolWeb/blob/main/.images_readme/volweblogo.png"  width="200" height="280" alt="VolWeb Title"/>
</p>

Volweb is a digital forensic memory analysis platform.  
The goal of VolWeb is to improve the efficiency of memory forensics by providing a centralized, visual and enhanced platform for incident responders and digital forensics investigators.  

VolWeb is based on volatility3, and this platform will evolve with the framework development.
This project is under active development, and this readme may or may not reflect the most up-to-date documentation.

Tool demo : https://www.forensicxlab.com/posts/cyberdefenders_brave/

**Volweb is still in development and will evolve quickly.**  
Update communications will be via twitter or by following this repo.


## Getting Started 🛠️
Volweb is fully dockerized and can be deployed in a production environment.
In order to deploy Volweb, you should follow these steps:

Download the latest release: https://github.com/k1nd0ne/VolWeb/releases

Then, navigate to the VolWeb directory and edit the **./docker/secret/volweb.env** file and add the different secret information.

Next, add your ssl certificate into the **nginx/ssl** folder (generated via certbot or openssl for example):
```
openssl genrsa > ./VolWeb/docker/nginx/ssl/privkey.pem
openssl req -new -x509 -key ./VolWeb/docker/nginx/ssl/privkey.pem > ./VolWeb/docker/nginx/ssl/fullchain.pem
```
**Don't forget to fill the different fields in the openssl certificate configuration.
Make sure that the privkey and fullchain files respectively have the same name as the example above.**

Finally, build the images and run the containers.
```
cd ./VolWeb/docker
docker-compose build
docker-compose up -d
```

The nginx logs can be found in the **/ngnix/log** folder.
By default the admin and user accounts created will have the following credentials:
```
admin:password
user:password
```
You can create more analyst accounts via the Django administration panel -> https://[VOLWEB HOSTED IP]/admin.

## Important Note 📄

The admin account cannot create analysis. Only use this account for analyst account creation and don't forget to change the passwords.

## Reset 🔄

⚠️ This procedure will delete all the uploaded memory dumps & database items ⚠️

```
cd ./VolWeb/docker
docker-compose down --rmi all --volumes
```

## Issues ⚠️
If you have found an issue, please raise it by opening an issue on github.


## Contact 📬
Contact me at k1nd0ne@mail.com for any questions regarding this tool.

# Wiki 📚
The full documentation will be available in the beta release of the project.

# Contributing

The project is opened for contribution, please follow the guideline bellow :

In order to contribute :
- Make a proposition first by opening an issue.
- **OR** contact me directly via k1nd0ne@mail.com.

## Setup your dev environment
To setup the dev environment follow these steps :

## Configure docker dev environment
```
cd docker
docker-compose -f docker-compose-dev.yml up
```

Run migrations and launch the webservice.

```
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py initadmin
python3 manage.py runserver
```

## Launch celery
```
celery -A investigations worker --loglevel=INFO
```

Once your feature has been developed, update the settings to production and test your code with the production docker-compose.yaml
Don't forget to clean the case directory.

**Volweb is in active development your features may take time to be integrated**  

# Next Release goals 📋

Checkout the roadmap : https://github.com/k1nd0ne/VolWeb/projects/1
