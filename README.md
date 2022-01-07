# JupyterHub Authenticator for SeaDataCloud VRE

This is an authenticator package for [JupyterHub](https://github.com/jupyterhub/jupyterhub), to be used in the Virtual Research Environment (VRE) developed in the scope of the European H2020 Project [SeaDataCloud](https://www.seadatanet.org/).

It is meant to be used in dockerized JupyterHub instances which then spawn single containers of JupyterNotebooks or possible other services. The Dockerfile included in this repository creates such a dockerized JupyterHub. It needs to mount the docker socket to function.

Please note that this software is a customized for the SeaDataCloud environment, e.g. it depends on the SeaDataCloud VRE API for authentication.


## Preconditions ##

* **Docker** must be installed and running to build and to run the images. The docker-socket will be mounted and used by the JupyterHub service.
* **docker-compose** must be installed and running to run the image the way it is described below.


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

Also adapt the .env file:

* **mandatory:** Set the value of `JUPYTERHUB_CRYPT_KEY` to the result of runing `openssl rand -hex 32`
* **mandatory:** Change the value of `ADMIN_PW`, as any user is allowed to login with this password.
* make sure you point to existing directory in `HOST_WHERE_ARE_USERDIRS`. This directory, like for example a NextCloud directory, must contain the users' directories (whose names are the usernames used for login, and they must contain a subdirectory called `files`). (Note that you can also set `MOUNT_USER_DIRS` to false in docker-compose.yml).
* make sure the value of `AUTH_URL` is a valid URL pointing to the SeaDataCloud VRE authentication endpoint (and it must be contained in the `WHITELIST_AUTH` setting in docker-compose.yml too). Use the `ADMIN_PW` if you have no access to the authentication endpoint.

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

More detailed instructions can be found in the [SeaDataCloud Deployment Documentation Wiki](https://github.com/SeaDataCloud/Documentation/wiki). For example, in the [instructions to deploy the SeaDataCloud ERDDAP service](https://github.com/SeaDataCloud/Documentation/wiki/Service:-ERDDAP-Subsetting-Service) or the [instructions to deploy the DIVA software](https://github.com/SeaDataCloud/Documentation/wiki/Service:-DIVA).

Some configuration examples can be found in the [SeaDataCloud VRE Config Repository](https://github.com/SeaDataCloud/vre-config/), in the config for the services _erddap_ and _diva_.


## Collaborators ##

Developed by Merret Buurman (DKRZ) in 2019-2020, based on a fork of [jupyterhub-webdavauthenticator](https://github.com/gher-ulg/jupyterhub-webdavauthenticator) by the research group GHER of the University of Liege, Belgium.


## Further documentation and some details ##

Also read JupyterHub's documentation, especially:

* https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html
* https://jupyterhub.readthedocs.io/en/stable/getting-started/networking-basics.html
* https://jupyterhub.readthedocs.io/en/stable/reference/index.html
* https://jupyterhub.readthedocs.io/en/stable/index-admin.html

### Adding a reverse proxy

**TODO**


### Adding SSL

These are the modifications on the docker-compose.yml to add SSL to the JupyterHub, so you don't need an external reverse proxy.

In the case of the VRE, the nginx should keep running on port 443 for the other services - that's why we will use port 444 in this example. Otherwise, you have to stop the proxy running on 443 beforehand, and remember to restart it afterwards!

* Make JupyterHub listen directly to outside, on port 444:

```
    # before:
    #expose:
    # - 8000
    # now:
    ports:
      - 443:8000
```

* Mount your SSL certs:

```
    volumes:
     - /root/wherever/cert/cert.pem:/srv/jupyterhub/ssl/certs/myhost_cert_and_chain.crt:rw
     - /root/wherever/cert/cert.key:/srv/jupyterhub/ssl/private/myhost.key:rw
```


* Switch on SSL. We have a convenience variable for this that you can set in the docker-compose:

```
   environment:
      #SSL_OFF: 'true'
      SSL_OFF: 'false'
```

This switches on SSL termination in jupyterhub_config.py:

```
SSL_OFF = os.environ.get('SSL_OFF', 'false')
SSL_OFF = (SSL_OFF.lower() == 'true')
if SSL_OFF:
    LOGGER.warn("SSL if off. Hopefully there's SSL termination happening somewhere else!")
else:
    c.JupyterHub.ssl_cert = '/srv/jupyterhub/ssl/certs/myhost_cert_and_chain.crt'
    c.JupyterHub.ssl_key = '/srv/jupyterhub/ssl/private/myhost.key'
```

* Restart the service (`docker-compose up -d && docker-compose logs --tail=100 -f`)

* In the case of the VRE, you must change the port in the dashboard config, so that users are sent to the new port 444! (Either temporarily on client side using the browser's HTML inspection tools, or temporarily on server side inside the dashboard container, or permanently in the dashboard config).

See https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html#if-ssl-termination-happens-outside-of-the-hub

To change back to proxied version, just undo the changes above.


### Change image of spawned containers

* Change the value for `DOCKER_JUPYTER_IMAGE` in .env.
* Restart the service by changing into the directory where the docker-compose.yml is sitting, and running `docker-compose down && docker-compose up -d && docker-compose logs --tail=100 - f`.
* Make sure to remove the existing containers `docker rm <containername>`, as running containers are not changed of course.
* Ideally, remove the old image: `docker image rm <old-imagename>`, so it does not take up space.


### Enough overall memory in the container?

Depending on how much memory you need, also increase overall memory for the containers in the .env file, by setting `MEMORY_LIMIT=5G`

This will be picked up in the jupyterhub_config.py:

```
MEMORY_LIMIT = os.environ.get('MEMORY_LIMIT', '2G')
c.Spawner.mem_limit = MEMORY_LIMIT
```

See https://github.com/jupyterhub/dockerspawner#memory-limits


### Mounted user directories


The users' directories are bind-mounted into the JuypterHub container from `/storage/on/host/userdirectories` to `/usr/share/userdirectories/`.

* The location on the host can be chosen, it is defined by `HOST_WHERE_ARE_USERDIRS`, which contains all the users' directories.
* The location inside the container can be chosen, but there is no reason to do so, as it is only visible to JupyterHub.

The specific user's directory is mounted into their spawned containers from `/storage/on/host/userdirectories/alice[/files]` to `/nextcloud` or to `/home/jovyan/work/nextcloud`.

* The location on the host can be chosen, it is defined by `HOST_WHERE_ARE_USERDIRS`, which contains all the users' directories, and `USERDIR_TEMPLATE_HOST`, which defines the user-specific part of the path:
  * `/{raw_username}/files` in case the original NextCloud data is used (e.g. via NFS-mount or directly from disk), which is the case on GRNET's VMs, or:
  * `/{raw_username}` if the user's data is contained directly in the directory that has the user's name, e.g. if the synchronized NextCloud data is used (as we only synchronize the content of the /files subdirectory), e.g. on DKRZ's servers.
* The location inside the spawned container can be chosen, it is defined by `USERDIR_IN_CONTAINER`. We strongly recommend not changing it, as the services may expect it in a certain location and fail if not found, or as this might confuse the users (e.g. they are used to finding their data in `/home/jovyan/` as it is common in JupyterNotebooks).



### username vs raw_username: Why raw_username?

**TODO**

See: https://github.com/jupyterhub/dockerspawner/issues/371


### Authentication API: What is expected?

The authentication API at the SeaDataCloud VRE expects a call via HTTP-POST, containing only this: `{'service_auth_token': token}`. The token comes from the Login form. In the SeaDataCloud case, the login form is hidden from the user. The webpage sends the login form and its contents via HTTP-POST to the JupyerHub (e.g. `https://someanimal.dkrz.de/diva/hub/login?next`) when a user clicks the button of a JupyterHub-based service:

```
<form id="form_diva" method="POST" action="https://someanimal.dkrz.de/diva/hub/login?next" target="_blank">
  <input type="hidden" name="vre_username" value="vre_larsondlkfjldsfj">
  <input type="hidden" name="vre_displayname" value="Jonathan Larson">
  <input type="hidden" name="service_auth_token" value="9dfksjldn34u">
  <input type="hidden" name="vre_URL" value="https://vre.seadatanet.org">
</form>
```

The current API URL is: `https://vre.seadatanet.org/service_auth`. It is provided by the config of the JupyterHub (setting `AUTH_URL: ${AUTH_URL}` in the `docker-compose.yml`'s environment section, will be used in `jupyterhub_config.yml` as `c.VREAuthenticator.auth_url`).


Check out the method `check_token_at_dashboard(token, dashboard_url)` and `authenticate(self, handler, data)` for this.


### JupyterHub base image

Currently (2020-10-20) the image is based on `jupyterhub/jupyterhub:1.2.0b1`, which is the latest image to date  (corresponds to digest `292a7ecea0fb` on 2020-10-20). It is based on JuypterHub commit [082f651](https://github.com/jupyterhub/jupyterhub/tree/082f6516a15de1c74657a57b5f9fee5a082c0600).

More up-to-date info is usually included in the Dockerfile in this repository.



### What operations on the file system are done by the prespawn method?

Check out the method `def pre_spawn_start(self, user, spawner)`.

If we said in config that we mount the userdirs, then the method `def prepare_user_directory(spawner)` is used:

If the user directory already exists in the filesystem, nothing is done. If it does not exist, it is created and chowned to the `uid:gid` passed in config (settings: `c.VREAuthenticator.userdir_user_id = RUN_AS_USER` and `c.VREAuthenticator.userdir_group_id = RUN_AS_GROUP`).



### Why an external docker network?

We are using an external network because we need to pass the network name to the docker spawner, and if we use an internal one, its name will be prefixed by the compose stack's name.

We pass it in the env variable `DOCKER_NETWORK_NAME`, it is passed to `c.DockerSpawner.network_name` and to `c.DockerSpawner.extra_host_config = { 'network_mode': DOCKER_NETWORK_NAME }` in the jupyterhub_config.py.


### RUN_AS_USER and RUN_AS_GROUP

By default, Jupyter Notebooks run as `1000:100` (https://groups.google.com/forum/#!topic/jupyter/-VJXHy5hnfM). But we tell it to run as other `uid:gid` in jupyterhub_config.py:


* Tell JHub to spawn as root:

```
c.DockerSpawner.extra_create_kwargs = {'user' : '0'}
```

* Tell spawned Notebooks to run as NB_UID:NB_GID, by adding these to the container environment: 

```
container_env['NB_UID'] = RUN_AS_USER
container_env['NB_GID'] = RUN_AS_GROUP
c.DockerSpawner.environment = container_env
```

Note: This only works automatically with Notebooks, other spawned containers have to implement this!

The `c.DockerSpawner.environment` can be used to pass arbitrary environment variables to the spawned containers!

### What to do if running as uid 33?

**TODO**

### Running Non-Jupter services

We're misusing the JupyterHub to run services which are not JupyterNotebooks. This works as long as the spawned containers provide any content at ____.

Some settings may have to be adjused.

* JupyterHub expects JupyterNotebooks to serve content on port 8888. If your service uses a different port, you have to tell JupyterHub. For example, ERDDAP always runs on port 8091 inside the container. You can use the env variable `SERVICE_PORT_IN_CONTAINER`, which is then passed to the Spawner:

```
c.Spawner.port = SERVICE_PORT_IN_CONTAINER

#c.DockerSpawner.container_port=8091
# Note: DockerSpawner.container_port is deprecated in dockerspawner 0.9.
```


### LazyConfig in JupyterHub

We cannot add volumes to the DockerSpawner one-by-one, as this causes a `TypeError: 'LazyConfigValue' object does not support item assignment`:

```
# no no:
c.DockerSpawner.volumes[host_dir1] = container_dir1
c.DockerSpawner.volumes[host_dir2] = container_dir2
c.DockerSpawner.volumes[host_dir3] = container_dir3
```

So we must make a dict and add it all at once:

```
c.DockerSpawner.volumes = {
    host_dir1 = container_dir1,
    host_dir2 = container_dir2,
    host_dir3 = container_dir3,
}

# or

volume_mounts = dict()
volume_mounts[host_dir1] = container_dir1
volume_mounts[host_dir2] = container_dir2
volume_mounts[host_dir3] = container_dir3
c.DockerSpawner.volumes = volume_mounts
```


### Test Run with DummyAuthenticator

In the `jupyterhub_config.py`, change the `c.JupyterHub.authenticator_class = 'vreauthenticator.VREAuthenticator'` to `c.JupyterHub.authenticator_class = 'dummyauthenticator.DummyAuthenticator'`, and add a line `c.DummyAuthenticator.password = "your-pw-of-choice"` (with a password of your choice here).

After a restart, you will be able to login using that password, for any username.



## Troubleshooting / previously solved problems ##

### Error 500 : Internal Server Error (1)

If you see this error `500 : Internal Server Error` in the browser after you try to log in, it might be a problem with the authentication whitelist!

You can check in the hub logs. If you find a line similar to this, then you may have to check the value of `WHITELIST_AUTH` in docker-compose.yml.

```
hub_diva_1  | WARNING:vreauthenticator.vreauthenticator:URL not permitted for authentication: https://vre.seadatanet.org
```

### Error 500 : Internal Server Error (2)

```
500 : Internal Server Error
Error in Authenticator.pre_spawn_start: IndexError list index out of range
```

If you see this error in the browser after you try to log in, it might be a problem with the mounts!

You can check in the hub logs. If you find a line similar to this, with two consecutive slashes `//`, then you may have to remove the pending slash from the value of `HOST_WHERE_ARE_USERDIRS` in /root/erddap/.env.

```
hub_erddap_1  | INFO:vreauthenticator.vreauthenticator:User directory will be: /myusername/files (bind-mounted from /mnt/sdc-nfs-data//myusername/files).
```

(This should be fixed since 2020-10-20.)


### Error "invalid characters for a local volume" (in log)

If the JupyterHub fails to spawn a container, and complains that: 

```
docker.errors.APIError: 400 Client Error: Bad Request ("create ./xxx/xxx: "./xxx/xxx" includes invalid characters for a local volume name, only "[a-zA-Z0-9][a-zA-Z0-9_.-]" are allowed. If you intended to pass a host directory, use absolute path")
```

The problem might be that you're trying to bind-mount a relative path (starting with `./` instead of `/`) in the `c.DockerSpawner.volumes` section in jupyterhub_config.py.


## Future work / TODOs ##

* Include Favicon
* Run the proxy separately (https://jupyterhub.readthedocs.io/en/stable/getting-started/config-basics.html#run-the-proxy-separately)



