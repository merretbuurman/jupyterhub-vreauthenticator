# Configuration file for Jupyter Hub
import os

c = get_config()


###
### Get all env variables
###

##
## Have to be set:
DOCKER_JUPYTER_IMAGE = os.environ['DOCKER_JUPYTER_IMAGE']
DOCKER_NETWORK_NAME = os.environ['DOCKER_NETWORK_NAME']
HOST_LOCATION_USERDIRS = os.environ['HOST_LOCATION_USERDIRS'] # without trailing slash!

##
## Optional, have defaults:
CONTAINER_PREFIX = os.environ.get('CONTAINER_PREFIX', 'jupyter')
MEMORY_LIMIT = os.environ.get('MEMORY_LIMIT', '2G')
HUB_IP = os.environ.get('HUB_IP', 'hub')
RUN_AS_USER = os.environ.get('RUN_AS_USER', None)
RUN_AS_GROUP = os.environ.get('RUN_AS_GROUP', None)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
ADMIN_PW = os.environ.get('ADMIN_PW', None)
WHITELIST_AUTH = os.environ.get('WHITELIST_AUTH', None)
WHITELIST_WEBDAV = os.environ.get('WHITELIST_WEBDAV', None)
HTTP_TIMEOUT = os.environ.get('HTTP_TIMEOUT', '60')
RUN_AS_USER = os.environ.get('RUN_AS_USER', 1000)
RUN_AS_GROUP = os.environ.get('RUN_AS_GROUP', 100)

## Some need to be int:
RUN_AS_USER = int(RUN_AS_USER)
RUN_AS_GROUP = int(RUN_AS_GROUP)
HTTP_TIMEOUT = int(HTTP_TIMEOUT)


##
## Memory limits
## https://github.com/jupyterhub/dockerspawner#memory-limits
c.Spawner.mem_limit = MEMORY_LIMIT

##
## spawn with Docker
c.JupyterHub.spawner_class = 'dockerspawner.DockerSpawner'

##
## Notebook Directory
## TODO: What is this setting good for?
## TODO: Do we really want to allow setting this from env?
##
## Define the directory where the Notebook opens: (TODO: Is this the correct word?)
## https://github.com/jupyterhub/dockerspawner#data-persistence-and-dockerspawner
## Please no trailing slash!
##
## Explicitly set notebook directory because we'll be mounting a host volume to
## it.  Most jupyter/docker-stacks *-notebook images run the Notebook server as
## user `jovyan`, and set the notebook directory to `/home/jovyan/work`.
## We follow the same convention.
notebook_dir = os.environ.get('DOCKER_NOTEBOOK_DIR') or '/home/jovyan/work'
c.DockerSpawner.notebook_dir = notebook_dir

##
## Mount the user directory
## We mount the <username>_sync directory, which is the synchronizer target directory!
## We mount it to a subdirectory of the Notebook directory (so that the sync dir does not get
## crowded with weird Jupyter stuff...
## The {username} comes from dockerspawner's volumenamingstrategy.py, and from JupyterHub's
## base handler which constructs a User object from the result of the authenticate() method,
## where we return a username (so we control that!)
c.DockerSpawner.volumes = {
    HOST_LOCATION_USERDIRS+'/{username}_sync/': notebook_dir+'/sync',
}

##
## Which docker image to be spawned
c.DockerSpawner.image = DOCKER_JUPYTER_IMAGE

##
## Prefix for the container's names:
c.DockerSpawner.prefix = CONTAINER_PREFIX

##
## Which authenticator to use
c.JupyterHub.authenticator_class = 'vreauthenticator.VREAuthenticator'

##
## Set the log level by value or name.
c.JupyterHub.log_level = LOG_LEVEL
if LOG_LEVEL == 'DEBUG':
  c.DockerSpawner.debug = True

##
## Timeout (in seconds) before giving up on a spawned HTTP server
## Once a server has successfully been spawned, this is the amount of time we
## wait before assuming that the server is unable to accept connections.
c.Spawner.http_timeout = HTTP_TIMEOUT

##
## Set whitelists for users
## All Marine-ID users are allowed to login (no whitelist):
#c.Authenticator.whitelist = whitelist = set()
## Currently, no admin users - we could add me there, but is my Marine-Id my name?Or my NextCloud username? I think the latter! # TODO
c.Authenticator.admin_users = admin = set()

##
## Enable passing env variables to containers from the 
## authenticate-method (which has the login form...)
c.Authenticator.enable_auth_state = True

##
## Logo file
c.JupyterHub.logo_file = "/usr/local/share/jupyter/hub/static/images/logo.png"


##
## White lists for authentication and WebDAV servers:
white_auth = [
    "https://b2drop.eudat.eu/remote.php/webdav",
    "https://dox.ulg.ac.be/remote.php/webdav",
    "https://dox.uliege.be/remote.php/webdav",
    "https://dummy",
]

white_webdav = [
    "https://b2drop.eudat.eu/remote.php/webdav",import os
c = get_config()


import logging
LOGGER = logging.getLogger()


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

HOST_NAME = os.environ['HOST_NAME']
PORT_NAME = os.environ['PORT_NAME']
JAVA_OPTS = os.environ['JAVA_OPTS'] # '-Xms800M -Xmx800M'


## Optional (have defaults)

SERVICE_PORT_IN_CONTAINER = os.environ.get('SERVICE_PORT_IN_CONTAINER', 8888)
LOG_OWNER = os.environ.get('LOG_OWNER', None)
MOUNT_USER_DIRS = os.environ.get('MOUNT_USER_DIRS', 'false')
HOST_WHERE_ARE_USERDIRS = os.environ.get('HOST_WHERE_ARE_USERDIRS', None)
HOST_WHERE_IS_SERVICE_DATA = os.environ.get('HOST_WHERE_IS_SERVICE_DATA', None)
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


## Some need to be int:
SERVICE_PORT_IN_CONTAINER = int(SERVICE_PORT_IN_CONTAINER)
HTTP_TIMEOUT = int(HTTP_TIMEOUT)
RUN_AS_USER = int(RUN_AS_USER)
RUN_AS_GROUP = int(RUN_AS_GROUP)

###################################
### Initialisations - IMPORTANT ###
###################################

container_env = {'SPAWNER_ENV_KEY': 'SPAWNER_ENV_VALUE'}
volume_mounts = dict()


################################
### ERDDAP specific settings ###
################################

# Tell ERDDAP itself its own URL (on the outside)
# What are these actually needed for, for redirects? TODO
container_env['HOST_NAME'] = HOST_NAME
container_env['PORT_NAME'] = PORT_NAME

# Pass Java Opts to ERDDAP/tomcat:
container_env['JAVA_OPTS'] = JAVA_OPTS

# Service data for ERDDAP:
volume_mounts[HOST_WHERE_IS_SERVICE_DATA.rstrip('/')] = '/service_data'

# Webapps for ERDDAP:
# TODO: Eventually ask Leo to put it into the image!
volume_mounts[HOST_WHERE_IS_SERVICE_DATA.rstrip('/')+'/erddap-webapps'] = '/opt/tomcat8/webapps'

# Logs for ERDDAP:
# TODO
#log_base = '/root/erddap/container_logs'
if LOG_OWNER is None:
    raise ValueError("Need a LOG_OWNER to mount logs to seomeone's NextCloud!")

log_base = '/nfs-import/'+LOG_OWNER+'/files/some_logs'
if not os.path.exists(log_base):
  LOGGER.warn('Creating: %s (%s:%s)' % (log_base, RUN_AS_USER, RUN_AS_GROUP))
  os.makedirs(log_base)
  os.chown(log_base, RUN_AS_USER, RUN_AS_GROUP)

volume_mounts[log_base]:'/opt/tomcat8/content/erddap/erddapDirectory/logs'

LOGGER.warn('Will mount logs to: %s' % log_base)

##############################
### File system and mounts ###
##############################

# Tell spawner which uid:gid to use:
c.VREAuthenticator.userdir_user_id = RUN_AS_USER
c.VREAuthenticator.userdir_group_id = RUN_AS_GROUP

c.DockerSpawner.notebook_dir = '/home/jovyan/work'

# Location of the user directories inside the containerized hub:
# (Note: We must bind-mount them there!)
c.VREAuthenticator.basedir_in_containerized_hub = '/usr/share/userdirectories/'

# Mount the user directory
# The {username} comes from dockerspawner's volumenamingstrategy.py, and from JupyterHub's
# base handler which constructs a User object from the result of the authenticate() method,
# where we return a username (so we control that!)

MOUNT_USER_DIRS = (MOUNT_USER_DIRS.lower() == 'true')
MOUNT_USER_DIRS = True
if MOUNT_USER_DIRS:

    # Check:
    if HOST_WHERE_ARE_USERDIRS is None:
        raise ValueError('We need "HOST_WHERE_ARE_USERDIRS" to mount the user directories!')

    # Bind-mount it into the spawned container:
    # raw_username: https://github.com/jupyterhub/dockerspawner/issues/371
    host_dir = HOST_WHERE_ARE_USERDIRS.rstrip('/')+'/{raw_username}/files'
    volume_mounts[host_dir] = '/nextcloud'
    # This has to be the first mount, as we fetch it from this list with index 0!
    # TODO: Problem, the dict does not have to be ordered!!
    
    # Tell the pre-spawn that we have it:
    c.VREAuthenticator.userdirs_are_mounted = True

# If we run as 33, we must overwrite "/usr/local/bin/start.sh" with an updated one:
if RUN_AS_USER == 33:
    
    if HOST_WHERE_IS_ADAPTED_START is None:
        raise ValueError("We need to know where ADAPTED_start.sh is. Please set HOST_WHERE_IS_ADAPTED_START.")

    volume_mounts[HOST_WHERE_IS_ADAPTED_START.rstrip()+'/ADAPTED_start.sh'] = '/usr/local/bin/start.sh'

#####################
### Misc settings ###
#####################

# WHere does the service run inside the container?
# JupyterHub by default # expects services to run at 8888,'so we must tell JHub where
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

# Set admin password
if ADMIN_PW is not None:
    c.VREAuthenticator.admin_pw = ADMIN_PW

# Which authenticator to use
c.JupyterHub.authenticator_class = 'vreauthenticator.VREAuthenticator'

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
# Not needed, as I copy the logo file to 
# /usr/local/share/jupyter/hub/static/images/logo.png
# in the Dockerfile! Otherwise, we'd use:
#c.JupyterHub.logo_file = "/usr/local/share/jupyter/hub/static/images/logo.png"

# Favicon # TODO
#cp /usr/local/share/jupyter/hub/static/images/favicon.ico /opt/conda/share/jupyterhub/static/favicon.ico


# Base URL. See c.JupyterHub.base_url in JupyterHub URL Scheme docs:
# https://test-jupyterhub.readthedocs.io/en/latest/reference/urls.html
container_env['BASE_URL'] = '' # TODO WHAT VALUE IF NONE?
if len(BASE_URL) > 0:
    c.JupyterHub.base_url = BASE_URL
    c.VREAuthenticator.base_url = BASE_URL
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
if RUN_AS_USER is not None or RUN_AS_GROUP is not None:
    c.DockerSpawner.extra_create_kwargs = {'user' : '0'}

# Tell spawned Notebooks to run as NB_UID:NB_GID.
# Note: This only works automatically with Notebooks, other spawned
# containers have to implement this!
# Also pass them to pre-spawn method of authenticator.

if RUN_AS_USER is not None:
    LOGGER.info('Politely requesting service to run as uid %s...' % RUN_AS_USER)
    container_env['NB_UID'] = RUN_AS_USER
    c.VREAuthenticator.userdir_user_id = RUN_AS_USER

if RUN_AS_GROUP is not None:
    LOGGER.info('Politely requesting service to run as group %s...' % RUN_AS_GROUP)
    container_env['NB_GID'] = RUN_AS_GROUP
    c.VREAuthenticator.userdir_group_id = RUN_AS_GROUP

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


    "https://dox.ulg.ac.be/remote.php/webdav",
    "https://dox.uliege.be/remote.php/webdav",
    "https://dummy",
]

'''
Helper to parse whitelisted servers, add the protocol to
them (https), and if http is allowed, also allow https.
'''
def add_to_whitelist(env_value_string, whitelist):
  # Allow comma separated list also with spaces:
  urls = env_value_string.split(',')
  for url in urls:
    url = url.strip()

    # If no protocol given, assume https:
    if not str.startswith(url, 'http'):
      url = 'https://%s' % url

    # Append:
    whitelist.append(url)

    # Always allow https:
    if str.startswith(url, 'http:'):
      whitelist.append(url.replace('http:', 'https:'))

if WHITELIST_AUTH is not None and isinstance(WHITELIST_AUTH, str):
  add_to_whitelist(WHITELIST_AUTH, white_auth)

if WHITELIST_WEBDAV is not None and isinstance(WHITELIST_WEBDAV, str):
  add_to_whitelist(WHITELIST_WEBDAV, white_webdav)

c.VREAuthenticator.allowed_auth_servers = white_auth 
c.VREAuthenticator.allowed_webdav_servers = white_webdav

##
## Set admin password
if ADMIN_PW is not None:
  c.VREAuthenticator.admin_pw = ADMIN_PW


###########################
## Run as different user ##
###########################

## Default is 1000:100
## See:
## https://groups.google.com/forum/#!topic/jupyter/-VJXHy5hnfM
## Two steps are needed:
## (1/2): Tell it to spawn as root:
c.DockerSpawner.extra_create_kwargs = {'user' : '0'}

## (2/2): Tell it to run as NB_UID:NB_GID:
## Note: We will also chown the directory to this user, in "pre_spawn_start"
container_env = {'SPAWNER_ENV_KEY': 'SPAWNER_ENV_VALUE'}

if RUN_AS_USER is not None:
  container_env['NB_UID'] = RUN_AS_USER

if RUN_AS_GROUP is not None:
  container_env['NB_GID'] = RUN_AS_GROUP

c.DockerSpawner.environment = container_env

# Tell spawner which uid:gid to use:
c.VREAuthenticator.userdir_user_id = RUN_AS_USER
c.VREAuthenticator.userdir_group_id = RUN_AS_GROUP


##################
## SSL settings ##
##################

## If hub runs inside a container, do not change these, but mount
## the cert and key to the correct location.
## Both must be set!

## Path to SSL certificate file for the public facing interface of the proxy 
c.JupyterHub.ssl_cert = '/srv/jupyterhub/ssl/certs/myhost_cert_and_chain.crt'

## Path to SSL key file for the public facing interface of the proxy
c.JupyterHub.ssl_key = '/srv/jupyterhub/ssl/private/myhost.key'


#######################
## Docker networking ##
#######################

##
## Pass the IP where the instances can access the JupyterHub instance
## The docker instances need access to the Hub, so the default loopback port doesn't work:
##from jupyter_client.localinterfaces import public_ips
##c.JupyterHub.hub_ip = public_ips()[0]
## Instead, containers will access hub by container name on the Docker network
c.JupyterHub.hub_ip = HUB_IP

##
## Connect containers to this Docker network
c.DockerSpawner.use_internal_ip = True
c.DockerSpawner.network_name = DOCKER_NETWORK_NAME

##
## Pass the network name as argument to spawned containers
## TODO: What for? Seems to work fine without it!
c.DockerSpawner.extra_host_config = { 'network_mode': DOCKER_NETWORK_NAME }

##
## On which port does the hub run (inside its container):
c.JupyterHub.port = 443

################
## Login form ##
################

##
## Custom login form
c.VREAuthenticator.custom_html = """<form action="/hub/login?next=" method="post" role="form">
  <div class="auth-form-header">
    Alternative Login
  </div>
  <div class='auth-form-body'>
    <h3>SeaDataCloud Virtual Research Environment</h3>
    
    <p>This is a JupyterHub for the SeaDataCloud VRE. This is a test login, you can <em>not</em> use your <em>Marine-ID</em>.</p>
    <p>If you see this and you did log in via Marine-Id, there has been an error on the server, and we would be extremely grateful if you could notify us (when it happened, what is your Marine-Id, ...)!</p>
    <div id="form_elements" style="display: none" >

        <label for="username_input">VRE username:</label>
        <input
          id="username_input"
          type="text"
          autocapitalize="off"
          autocorrect="off"
          class="form-control"
          name="auth_username"
          value=""
          tabindex="1"
          autofocus="autofocus"
        />

        <label for='password_input'>VRE password:</label>
        <input
          type="password"
          class="form-control"
          name="auth_password"
          id="password_input"
          tabindex="2"
        /> 

        <label for='auth_url_input'>Authentication URL:</label>
        <input
          type="text"
          class="form-control"
          name="auth_url"
          id="auth_url_input"
          value = "https://dummy"
        />

        <p><br/>Only for testing:</p>

        <label for='token_input'>VRE token:</label>
        <input
          type="text"
          class="form-control"
          name="auth_token"
          id="token_input"
        />

        <p><br/>WebDAV info is optional!</p>

        <label for='webdav_mount_user_input'>WebDAV Username (optional):</label>
        <input
          type="text"
          class="form-control"
          name="webdav_mount_username"
          id="webdav_mount_user_input"
          xstyle="display: none"
          value = "santaclaus"
        />

        <label for='webdav_mount_password_input'>WebDAV password (optional):</label>
        <input
          type="password"
          class="form-control"
          name="webdav_mount_password"
          id="webdav_mount_password_input"
        /> 

        <label for='webdav_mount_url_input'>WebDAV URL (optional):</label>
        <input
          type="text"
          class="form-control"
          name="webdav_mount_url"
          id="webdav_mount:url_input"
          xstyle="display: none"
          value = "https://dummy"
        />

        <label for='fileselection_path_input'>File selection (path):</label>
        <input
          type="text"
          class="form-control"
          name="fileselection_path"
          id="fileselection_path_input"
          value = "/Photos/Hummingbird.jpg"
        />

        <input
          type="submit"
          id="login_submit"
          class='btn btn-jupyter'
          value='Sign In'
          tabindex="3"
        />
    </div>
  </div>
</form>
<script>
function parse_query_string(query) {
  var vars = query.split("&");
  var query_string = {};
  for (var i = 0; i < vars.length; i++) {
    var pair = vars[i].split("=");
    // If first entry with this name
    if (typeof query_string[pair[0]] === "undefined") {
      query_string[pair[0]] = decodeURIComponent(pair[1]);
      // If second entry with this name
    } else if (typeof query_string[pair[0]] === "string") {
      var arr = [query_string[pair[0]], decodeURIComponent(pair[1])];
      query_string[pair[0]] = arr;
      // If third or later entry with this name
    } else {
      query_string[pair[0]].push(decodeURIComponent(pair[1]));
    }
  }
  return query_string;
}
// substitute username and token from query string if provided
// and submit form for login.
var query = window.location.search.substring(1);
var qs = parse_query_string(query);
if (qs.username) {
  document.getElementById("username_input").value  = qs.username;
}
if (qs.password) {
   document.getElementById("password_input").value  = qs.password;
}
if (qs.webdav_url) {
   document.getElementById("auth_url_input").value  = qs.auth_url;
}
if (qs.token) {
   document.getElementById("token_input").value  = qs.token;
   document.getElementsByTagName("form")[0].submit();
}
else {
  document.getElementById("form_elements").style.display = "block"
}
</script>


"""

