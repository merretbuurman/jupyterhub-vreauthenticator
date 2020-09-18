import os
c = get_config()


import logging
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
VERSION = '20200428'
LOGGER.info('Jupyter Config version %s' % VERSION)


#######################################
### Environment variables           ###
### to be set in docker-compose.yml ###
#######################################

## Mandatory for functioning:

HUB_IP = os.environ['HUB_IP'] # hub's hostname inside docker network
DOCKER_NETWORK_NAME = os.environ['DOCKER_NETWORK_NAME']
DOCKER_JUPYTER_IMAGE = os.environ['DOCKER_JUPYTER_IMAGE']
AUTH_URL = os.environ['AUTH_URL']


## Mandatory for ERDDAP only:

HOST_NAME = os.environ.get('HOST_NAME', None)
PORT_NAME = os.environ.get('PORT_NAME', None)
JAVA_OPTS = os.environ.get('JAVA_OPTS', None) # '-Xms800M -Xmx800M'
HOST_WHERE_IS_ERDDAP_DATA = os.environ.get('HOST_WHERE_IS_ERDDAP_DATA', None)


## Optional (have defaults)

SERVICE_PORT_IN_CONTAINER = os.environ.get('SERVICE_PORT_IN_CONTAINER', 8888)
SSL_OFF = os.environ.get('SSL_OFF', 'false')
MEMORY_LIMIT = os.environ.get('MEMORY_LIMIT', '2G')
HTTP_TIMEOUT = os.environ.get('HTTP_TIMEOUT', '60')
CONTAINER_PREFIX = os.environ.get('CONTAINER_PREFIX', 'jupyter')
ADMIN_PW = os.environ.get('ADMIN_PW', None)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
BASE_URL=os.environ.get('BASE_URL', '')
WHITELIST_AUTH = os.environ.get('WHITELIST_AUTH', None)
SHUTDOWN_ON_LOGOUT = os.environ.get('SHUTDOWN_ON_LOGOUT', 'false')
FILESELECTOR_URL = os.environ.get('FILESELECTOR_URL', None) # TODO needed?
RUN_AS_USER = os.environ.get('RUN_AS_USER', 1000)
RUN_AS_GROUP = os.environ.get('RUN_AS_GROUP', 100)
HOST_WHERE_IS_ADAPTED_START = os.environ.get('HOST_WHERE_IS_ADAPTED_START', None) # only needed if RUN_AS_USER is 33!
MOUNT_USER_DIRS = os.environ.get('MOUNT_USER_DIRS', 'false')
HOST_WHERE_ARE_USERDIRS = os.environ.get('HOST_WHERE_ARE_USERDIRS', 'not-set')
USERDIR_TEMPLATE_HOST = os.environ.get('USERDIR_TEMPLATE_HOST', '/{raw_username}/files')
USERDIR_IN_CONTAINER = os.environ.get('USERDIR_IN_CONTAINER', '/nextcloud')

## Some need to be int:
SERVICE_PORT_IN_CONTAINER = int(SERVICE_PORT_IN_CONTAINER)
HTTP_TIMEOUT = int(HTTP_TIMEOUT)
RUN_AS_USER = int(RUN_AS_USER)
RUN_AS_GROUP = int(RUN_AS_GROUP)

# Some need rsplit
HOST_WHERE_ARE_USERDIRS = HOST_WHERE_ARE_USERDIRS.rstrip()
USERDIR_TEMPLATE_HOST = USERDIR_TEMPLATE_HOST.strip('/')
USERDIR_IN_CONTAINER = USERDIR_IN_CONTAINER.rstrip('/')





###################################
### Initialisations - IMPORTANT ###
###################################

# These have to be pre-initialized, and assigned at the end.
# Otherwise:
# TypeError: 'LazyConfigValue' object does not support item assignment

container_env = dict()
volume_mounts = dict()


##############################
### DIVA specific settings ###
##############################

if True:
    LOGGER.info('Config for DIVA or other Notebooks...')
    pass
    # There is None!

################################
### ERDDAP specific settings ###
################################

if True:
    LOGGER.info('Config for ERDDAP...')

    if (HOST_NAME is None or PORT_NAME is None or JAVA_OPTS is None or
        HOST_WHERE_IS_ERDDAP_DATA is None or SERVICE_PORT_IN_CONTAINER is None):
        raise ValueError("One or more of the ERDDAP-specific env vars is missing.")

    # Tell ERDDAP itself its own URL (on the outside)
    # What are these actually needed for, for redirects? TODO
    container_env['HOST_NAME'] = HOST_NAME
    container_env['PORT_NAME'] = PORT_NAME

    # Pass Java Opts to ERDDAP/tomcat:
    container_env['JAVA_OPTS'] = JAVA_OPTS

    # Service data and Webapps for ERDDAP:
    HOST_WHERE_IS_ERDDAP_DATA = HOST_WHERE_IS_ERDDAP_DATA.rstrip()
    volume_mounts[HOST_WHERE_IS_ERDDAP_DATA] = '/service_data'
    volume_mounts[HOST_WHERE_IS_ERDDAP_DATA+'/erddap-webapps'] = '/opt/tomcat8/webapps'
    # TODO: Eventually ask Leo to put WebApps into the image!

##############################
### File system and mounts ###
##############################

c.DockerSpawner.notebook_dir = '/home/jovyan/work'

# Location of the user directories inside the containerized hub:
# (Note: We must bind-mount them there!)
c.VREAuthenticator.basedir_in_containerized_hub = '/usr/share/userdirectories/'
c.VREAuthenticator.basedir_on_host = HOST_WHERE_ARE_USERDIRS

# Mount the user directory
# The {username} comes from dockerspawner's volumenamingstrategy.py, and from JupyterHub's
# base handler which constructs a User object from the result of the authenticate() method,
# where we return a username (so we control that!)

MOUNT_USER_DIRS = (MOUNT_USER_DIRS.lower() == 'true')
if MOUNT_USER_DIRS:

    # Bind-mount it into the spawned container:
    # Why raw_username? https://github.com/jupyterhub/dockerspawner/issues/371
    #host_dir = HOST_WHERE_ARE_USERDIRS +'/'+ '{username}'
    #host_dir = HOST_WHERE_ARE_USERDIRS +'/'+ '{raw_username}/files'
    #host_dir = HOST_WHERE_ARE_USERDIRS +'/'+ '{raw_username}'
    host_dir  = HOST_WHERE_ARE_USERDIRS +'/'+ USERDIR_TEMPLATE_HOST
    LOGGER.info('IMPORTANT: Will be mounted: %s' % host_dir)
    volume_mounts[host_dir] = USERDIR_IN_CONTAINER
    # This has to be the first mount, as we fetch it from this list with index 0!
    # TODO: Problem, the dict does not have to be ordered!!
    
    # Tell the pre-spawn that we have it, so it does the preparation of it:
    c.VREAuthenticator.userdirs_are_mounted = True

# If we run as 33, we must overwrite "/usr/local/bin/start.sh" with an updated one:
if RUN_AS_USER == 33 and HOST_WHERE_IS_ADAPTED_START is None:
    raise ValueError("We need to know where ADAPTED_start.sh is. Please set HOST_WHERE_IS_ADAPTED_START.")

if RUN_AS_USER == 33:
    volume_mounts[HOST_WHERE_IS_ADAPTED_START.rstrip()+'/ADAPTED_start.sh'] = '/usr/local/bin/start.sh'

#####################
### Misc settings ###
#####################

# Where does the service run inside the container?
# JupyterHub by default expects services to run at 8888, so we must tell JHub where
# to access it instead. E.g. ERDDAP always runs on port 8091 inside the container.
c.Spawner.port = SERVICE_PORT_IN_CONTAINER
#c.DockerSpawner.port=SERVICE_PORT_IN_CONTAINER
#c.DockerSpawner.container_port=SERVICE_PORT_IN_CONTAINER
# Note: DockerSpawner.container_port is deprecated in dockerspawner 0.9.

# Shutdown containers on logout (defaults to False):
# https://jupyterhub.readthedocs.io/en/stable/api/app.html#jupyterhub.app.JupyterHub.shutdown_on_logout
SHUTDOWN_ON_LOGOUT = (SHUTDOWN_ON_LOGOUT.lower() == 'true')
c.JupyterHub.shutdown_on_logout = SHUTDOWN_ON_LOGOUT

# Set the log level by value or name.
c.JupyterHub.log_level = LOG_LEVEL
if LOG_LEVEL == 'DEBUG':
    c.DockerSpawner.debug = True

# Timeout (in seconds) before giving up on a spawned HTTP server
# Once a server has successfully been spawned, this is the amount of time we
# wait before assuming that the server is unable to accept connections.
c.Spawner.http_timeout = HTTP_TIMEOUT

# Memory limits
# https://github.com/jupyterhub/dockerspawner#memory-limits
c.Spawner.mem_limit = MEMORY_LIMIT

# Which URL to use to authenticate at:
c.VREAuthenticator.auth_url = AUTH_URL

# Which URL to use to call the file selector:
# TODO STILL NEEDED?
container_env['FILESELECTOR_URL'] = ''
if FILESELECTOR_URL is not None:
    container_env['FILESELECTOR_URL'] = FILESELECTOR_URL

# Which authenticator to use
c.JupyterHub.authenticator_class = 'vreauthenticator.VREAuthenticator'

# Set admin password
if ADMIN_PW is not None:
    c.VREAuthenticator.admin_pw = ADMIN_PW

# Spawn with Docker
c.JupyterHub.spawner_class = 'dockerspawner.DockerSpawner'

# Which docker image to be spawned
c.DockerSpawner.image = DOCKER_JUPYTER_IMAGE

# Prefix for the container's names:
c.DockerSpawner.prefix = CONTAINER_PREFIX

# How will containers be called:
# Need to use raw_username here, because of bug:
#https://github.com/jupyterhub/dockerspawner/issues/371
#c.DockerSpawner.name_template = CONTAINER_PREFIX+'-{username}'
c.DockerSpawner.name_template = CONTAINER_PREFIX+'-{raw_username}'


# Enable passing env variables to containers from the 
# authenticate-method (which has the login form...)
c.Authenticator.enable_auth_state = True

# Logo file
c.JupyterHub.logo_file = "/srv/jupyterhub/archive/logo.png"

# Favicon # TODO
#cp /usr/local/share/jupyter/hub/static/images/favicon.ico /opt/conda/share/jupyterhub/static/favicon.ico


# Base URL. See c.JupyterHub.base_url in JupyterHub URL Scheme docs:
# https://test-jupyterhub.readthedocs.io/en/latest/reference/urls.html
container_env['BASE_URL'] = '' # TODO WHAT VALUE IF NONE?
if len(BASE_URL) > 0:
    c.JupyterHub.base_url = BASE_URL
    container_env['BASE_URL'] = BASE_URL

############################
## Whitelist auth servers ##
############################

whitelist = []

if WHITELIST_AUTH is None:
    urls = []
else:
    urls = WHITELIST_AUTH.split(',')

for url in urls:
    url = url.strip()

    if str.startswith(url, 'http'):
        whitelist.append(url)
    else:
        whitelist.append('https://' + url)

    if str.startswith(url, 'http:'):
        whitelist.append(url.replace('http:', 'https:'))

LOGGER.info('Allowing these auth servers: %s' % whitelist)
c.VREAuthenticator.allowed_auth_servers = whitelist 


###########################
## Run as different user ##
###########################

# Default is 1000:100. See:
# https://groups.google.com/forum/#!topic/jupyter/-VJXHy5hnfM

# 1. Tell JHub to spawn as root:
c.DockerSpawner.extra_create_kwargs = {'user' : '0'}

# Tell spawned Notebooks to run as NB_UID:NB_GID.
# Note: This only works automatically with Notebooks, other spawned
# containers have to implement this!

LOGGER.info('Politely requesting service to run as uid:gid %s:%s...' % (RUN_AS_USER, RUN_AS_GROUP))
LOGGER.warn('Non-Jupyter-Notebooks often ignore the request to run as uid:gid %s:%s...' % (RUN_AS_USER, RUN_AS_GROUP))
container_env['NB_UID'] = RUN_AS_USER
container_env['NB_GID'] = RUN_AS_GROUP

# Also pass them to pre-spawn method of authenticator.
LOGGER.info('Passing %s:%s to the authenticator...' % (RUN_AS_USER, RUN_AS_GROUP))
c.VREAuthenticator.userdir_user_id = RUN_AS_USER
c.VREAuthenticator.userdir_group_id = RUN_AS_GROUP
c.VREAuthenticator.admin_pw = ADMIN_PW

# Important note:
# If we run as uid 33, we must overwrite "/usr/local/bin/start.sh" with
# an updated script. See section on mounts (c.DockerSpawner.volumes) for this!


########################
### Network settings ###
########################

# User containers will access hub by container name on the Docker network
# Has to be set to the name of the jupyterhub container, for the containers to reach it.

# Where other services contact the hub, e.g. in a Docker network. Not sure what other services.
c.JupyterHub.hub_connect_ip = HUB_IP
#https://jupyterhub.readthedocs.io/en/stable/getting-started/networking-basics.html#configure-the-hub-if-the-proxy-or-spawners-are-remote-or-isolated

# The proxy's ip, where JHub is available to users. JHub is only contacted by the nginx proxy via docker network,
# so we set this to the hostname inside the docker-network. This setting does not seem to be necessary, but if we
# don't set it, we get this in the log:
# JupyterHub app:2675] JupyterHub is now running at http://:8000/
c.JupyterHub.ip = HUB_IP
#https://jupyterhub.readthedocs.io/en/stable/getting-started/networking-basics.html#set-the-proxy-s-ip-address-and-port

# Where spawner and proxy contact the hub: Defaults to localhost, which should be okay, as they sit in the same container.
#c.JupyterHub.hub_ip = HUB_IP
#https://jupyterhub.readthedocs.io/en/stable/getting-started/networking-basics.html#configure-the-hub-if-the-proxy-or-spawners-are-remote-or-isolated

# Connect containers to this Docker network
c.DockerSpawner.network_name = DOCKER_NETWORK_NAME

# Pass the network name as argument to spawned containers
c.DockerSpawner.extra_host_config = { 'network_mode': DOCKER_NETWORK_NAME }

# TODO DOCUMENT
c.DockerSpawner.use_internal_ip = True

# Off, because nginx proxy will do the SSL termination
#https://jupyterhub.readthedocs.io/en/stable/getting-started/security-basics.html#if-ssl-termination-happens-outside-of-the-hub
SSL_OFF = (SSL_OFF.lower() == 'true')
if SSL_OFF:
    LOGGER.warn("SSL if off. Hopefully there's SSL termination happening somewhere else!")
else:
    # Path to SSL certificate file for the public facing interface of the proxy
    #  When setting this, you should also set ssl_key
    c.JupyterHub.ssl_cert = '/srv/jupyterhub/ssl/certs/myhost_cert_and_chain.crt'

    # Path to SSL key file for the public facing interface of the proxy
    #  When setting this, you should also set ssl_cert
    c.JupyterHub.ssl_key = '/srv/jupyterhub/ssl/private/myhost.key'
    
    
###########################
### Finally - IMPORTANT ###
###########################

# Pass env vars to spawner:
c.DockerSpawner.environment = container_env

# Pass all mounts to spawner:
if len(volume_mounts) > 0:
    LOGGER.info('Requested volume mounts into the spawned containers: %s' % volume_mounts)
    c.DockerSpawner.volumes = volume_mounts
else:
    LOGGER.warn('No volume mounts into the spawned containers were requested.')

