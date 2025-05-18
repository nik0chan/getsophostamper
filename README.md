# getsophostamper

- Description 
Docker service that given an organization computer name returns his Sophos tamper protection

- Requirements 
You must create a config file Sophos_Central.config with the following fields: 

[DEFAULT]
ClientID:
ClientSecret:

Docker service must be installed. 

- Launching microservice 

To start micro-service: 

docker run -p 80:5000 $(docker build -q .)

This brings up a webserver on 80 ports. WARNING! It's insecure, you have to configure an ingress to perform authentication, access control, encription, etc 

- Query for endpoint tamper

Once microservice is running open a browser on:

http://localhost/get-tamper-password?hostname=enpoint_name 

