# JupyterHub Authenticator for SeaDataCloud VRE

This is an authenticator package for [JupyterHub](https://github.com/jupyterhub/jupyterhub), to be used in the Virtual Research Environment (VRE) developed in the scope of the European H2020 Project [SeaDataCloud](https://www.seadatanet.org/).

It is meant to be used in dockerized JupyterHub instances which then spawn single containers of JupyterNotebooks or possible other services. The Dockerfile included in this repository creates such a dockerized JupyterHub. It needs to mount the docker socket to function.

Please note that this software is a customized for the SeaDataCloud environment, e.g. it depends on the SeaDataCloud VRE API for authentication.


## Preconditions ##

Docker must be installed and running to build the images.

Docker and docker-compose must be installed and running to run the image the way it is described below. The docker-socket will be mounted and used by the JupyterHub service.


## Build ##

This builds a docker image containing jupyterhub with _dockerspawner_ and with the _vreauthenticator_ installed.

It runs entirely without SSL and does not expose any ports to the outside world, assuming that a reverse proxy with SSL termination is running in front of it.

```
git clone https://github.com/merretbuurman/jupyterhub-vreauthenticator.git
cd jupyterhub-vreauthenticator

today=`date +'%Y%m%d'`
docker build -t jupyterhub_vre:${today} .

```

## Usage ##

Make a directory from which to run the service and add the necessary files.

```
mkdir myproject
cd myproject

git clone https://github.com/merretbuurman/jupyterhub-vreauthenticator.git
cp jupyterhub-vreauthenticator/docker-compose.yml ./
cp jupyterhub-vreauthenticator/jupyterhub_config.py ./
cp jupyterhub-vreauthenticator/env-commented ./env-commented
cp jupyterhub-vreauthenticator/env-example ./.env

```

Now adapt the docker-compose.yml file:

* adapt the image name to match `jupyterhub_vre:${today}` (now called `jupyterhub_vre:20201020`)
* optional: adapt the service name (now called `hub_xxx`). If you adapt it, also adapt the `HUP_IP` value in .env. They must have the same value.

Also adapt the `.env` file:

* **mandatory:** Set the value of `JUPYTERHUB_CRYPT_KEY` to the result of runing `openssl rand -hex 32`
* **mandatory:** Change the value of `ADMIN_PW`, as any user is allowed to login with this password.
* make sure you point to existing directory in `HOST_WHERE_ARE_USERDIRS`. This directory, like for example a NextCloud directory, must contain the users' directories (whose names are the usernames used for login, and they must contain a subdirectory called `files`). (Note that you can also set `MOUNT_USER_DIRS` to false in docker-compose.yml).
* make sure the value of `AUTH_URL` is a valid URL pointing to the SeaDataCloud VRE authentication endpoint (and it must be contained in the `WHITELIST_AUTH:` setting in docker-compose.yml too). Use the `ADMIN_PW` if you have no access to the authentication endpoint.

Explanations of the values can be found in `env-commented`. 

Create the docker-network used by the JupyterHub to communicate with its spawned containers:

```
docker network create vre
```

Then, start the service by running:

```
docker-compose up -d && docker-compose logs --tail=100 -f

# stop and remove it:
#docker-compose down

# remove and restart:
#docker-compose up -d && docker-compose logs --tail=100 -f
```

This will launch the JupyterHub, ready to spawn python JupyterNotebook containers for the users and to mount the user's data from disk. 

More detailed instructions can be found in the [SeaDataCloud Deployment Documentation Wiki] (https://github.com/SeaDataCloud/Documentation/wiki). For example, in the [instructions to deploy the SeaDataCloud ERDDAP service](https://github.com/SeaDataCloud/Documentation/wiki/Service:-ERDDAP-Subsetting-Service) or the [instructions to deploy the DIVA software](https://github.com/SeaDataCloud/Documentation/wiki/Service:-DIVA).

Some configuration examples can be found in the [SeaDataCloud VRE Config Repository](https://github.com/SeaDataCloud/vre-config/), in the config for the services _erddap_ and _diva_.


## Collaborators ##

Developed by Merret Buurman (DKRZ) in 2019-2020, based on a fork of [jupyterhub-webdavauthenticator](https://github.com/gher-ulg/jupyterhub-webdavauthenticator) by the research group GHER of the University of Liege, Belgium.


## Further documentation and some details ##


### Adding a reverse proxy

**TODO**


### Adding SSL

**TODO**


### Authentication API: What is expected?

**TODO**


### JupyterHub base image

Currently (2020-10-20) the image is based on `jupyterhub/jupyterhub:1.2.0b1`, which is the latest image to date  (corresponds to digest `292a7ecea0fb` on 2020-10-20). It is based on JuypterHub commit [082f651](https://github.com/jupyterhub/jupyterhub/tree/082f6516a15de1c74657a57b5f9fee5a082c0600).

More up-to-date info is usually included in the Dockerfile in this repository.


### username vs raw_username

**TODO**


### Why an external docker network?

We are using an external network, because we need to pass the network name to the docker spawner, and if we use an internal one, its name will be prefixed by the compose stack's name.



## Troubleshooting ##

**TODO**


## Future work / TODOs ##

* TODO: Include Favicon

