#!/bin/bash

function generate_self_signed_certificate(){
    echo "Would you like to generate a self-signed certificate ?"
    echo "1. Yes I don't have a certificate"
    echo "2. No my certificate is already placed in the nginx/ssl (fullchain+privkey)"
    read choice

    case $choice in
      1)
        openssl genrsa > docker/minio/privkey.pem
        openssl req -new -x509 -key docker/minio/privkey.pem > docker/minio/fullchain.pem
        cp docker/minio/privkey.pem docker/nginx/ssl/privkey.pem
        cp docker/minio/fullchain.pem docker/nginx/ssl/fullchain.pem
        ;;
      2)
        echo "No cert was produced."
        ;;
      *)
        echo "Invalid choice"
        ;;
    esac
}

function prompt_standard() {
  echo "Enter the fqdn or IP for your VolWeb instance:"
  read fqdn_or_ip

  echo "Enter the Django secret key:"
  read django_secret

  echo "Enter the MINIO/AWS access key ID:"
  read aws_access_key

  echo "Enter the MINIO/AWS secret access key:"
  read aws_secret_key

  echo "Enter the Postgres username:"
  read postgres_user

  echo "Enter the Postgres password:"
  read postgres_password

  sed -e "s|fqdn-or-ip-volweb-plateform|$fqdn_or_ip|g" \
      -e "s|SECRET_KEY_HERE|$django_secret|g" \
      -e "s|us-east-1|$aws_region|g" \
      -e "s|CLOUD_KEY_ID|$aws_access_key|g" \
      -e "s|CLOUD_KEY|$aws_secret_key|g" \
      -e "s|VOLWEB_DB_USER|$postgres_user|g" \
      -e "s|VOLWEB_DB_PASSWORD|$postgres_password|g" \
      docker/.env.prod.example > docker/.env

  docker-compose -f docker/docker-compose.yml down
  docker-compose -f docker/docker-compose.yml up -d
}

function prompt_aws() {
  echo "Enter the fqdn or IP for your VolWeb instance:"
  read fqdn_or_ip

  echo "Enter the Django secret key:"
  read django_secret

  echo "Enter the AWS region (e.g., us-east-1):"
  read aws_region

  echo "Enter the AWS access key ID:"
  read aws_access_key

  echo "Enter the AWS secret access key:"
  read aws_secret_key

  echo "Enter the Postgres username:"
  read postgres_user

  echo "Enter the Postgres password:"
  read postgres_password

  sed -e "s|fqdn-or-ip-volweb-plateform|$fqdn_or_ip|g" \
      -e "s|SECRET_KEY_HERE|$django_secret|g" \
      -e "s|us-east-1|$aws_region|g" \
      -e "s|CLOUD_KEY_ID|$aws_access_key|g" \
      -e "s|CLOUD_KEY|$aws_secret_key|g" \
      -e "s|VOLWEB_DB_USER|$postgres_user|g" \
      -e "s|VOLWEB_DB_PASSWORD|$postgres_password|g" \
      docker/.env.aws.example > docker/.env.aws

  docker-compose -f docker/docker-compose-aws.yml down
  docker-compose -f docker/docker-compose-aws.yml up -d

}

echo "Choose your installation method:"
echo "1. Standard"
echo "2. AWS"

read choice

case $choice in
  1)
    generate_self_signed_certificate
    prompt_standard
    echo "--------------VOLWEB IS STARTED----------"
    echo "Please follow the steps bellow:"
    echo "1. Navigate to https://$fqdn_or_ip:9000 and https://$fqdn_or_ip:9000"
    echo "2. Navigate to https://$fqdn_or_ip"
    ;;
  2)
    prompt_aws
    ;;
  *)
    echo "Invalid choice"
    ;;
esac
