'''
This is an authenticator class for JupyterHubs (based on 
    jupyterhub.auth.Authenticator) to login to JupyterHub services with
    valid WebDAV credentials and access to a WebDAV server.

*************
Please note the configuration options for this (in jupyterhub_config.py):

c.WebDAVAuthenticator.allowed_webdav_servers = ["https://xyz.com", "https://abc.fr"]
c.WebDAVAuthenticator.allowed_mount_servers = ["https://xyz.com", "https://abc.fr"]
c.WebDAVAuthenticator.hub_is_dockerized = True|False|None
c.WebDAVAuthenticator.admin_pw = 'skdlaiuewajhwbjuyzgdfhkeshfrsyerhk'
c.WebDAVAuthenticator.custom_html = """<form action="/hub/login?next=" method="post" role="form">..."""

*************
You must specify whether JupyterHub is running inside a docker container or
directly on the docker host. Two ways to do this:

    (1) A config item ("hub_is_dockerized") in jupyterhub_config.py. This takes
    precedence over the environment variable.

    (2) An environment variable  called "HUB_IS_DOCKERIZED", which can easily
    be passed from the docker-compose.yml in case JupyterHub is containerized.
    The values 1, '1', 'true', 'True', and 'TRUE' all evaluate to True.



'''

import mechanicalsoup
import warnings
import requests
from urllib.parse import parse_qs, urlparse, urlencode
import xml.etree.ElementTree as ET
import sys
import os

from tornado import gen
from traitlets import Unicode, List, Bool

from jupyterhub.auth import Authenticator
import webdav.client
from urllib.parse import urlparse

import logging

from . import utils

# Configure logging:
LOGGER = logging.getLogger(__name__)

# Default log level seems to be WARNING and ERROR.
# Adapt log level for this module here:
root = logging.getLogger()
default_lvl = 'INFO'
lvl = os.environ.get('LOG_LEVEL',  default_lvl)
lvl = logging.getLevelName(lvl)
try:
    root.setLevel(lvl)
except ValueError as e:
    LOGGER.warn('Could not understand log level "%s". Using "%s" instead.' % (lvl, default_lvl))
    root.setLevel(logging.getLevelName(default_lvl))

# The default format seems to be:
# WARNING:packagename.modulename:This is the Message
# If we add a different formatter, the formatted messages will be printed
# in addition to the messages formatted as above (so every message will be
# double).
#import sys
#formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(name)s: %(message)s')
#handler = logging.StreamHandler(sys.stdout)
#handler.setFormatter(formatter)
#root.addHandler(handler )




# User id and group id for the user's directory. Must match those used in the
# spawned container. Default is 1000:100. In the container they can be changed,
# and are set to the env vars 'NB_UID', 'NB_GID', but those are only available
# inside the container, so we cannot use them here.
# See:
# https://github.com/jupyter/docker-stacks/blob/7a3e968dd21268c4b7a6746458ac34e5c3fc17b9/base-notebook/Dockerfile#L10
USERDIR_OWNER_ID_DEFAULT = 1000
USERDIR_GROUP_ID_DEFAULT = 100



'''
Used for authentication via WebDAV.

The username and password are verified against a WebDAV
server, whose URL is passed as arg.

:return: The username (non-empty string) if the authentication
    was successful, or None otherwise.
'''
def check_webdav(username,password,url):
    LOGGER.debug("Calling check_webdav()...")

    purl = urlparse(url)

    # Try with webdav.client
    LOGGER.debug('Authenticate using webdav.client...')
    success = False
    client = webdav.client.Client({
        'webdav_hostname': purl.scheme + "://" + purl.hostname,
        'webdav_login':    username,
        'webdav_password': password})

    try:
        success = client.check(purl.path)
    except webdav.exceptions.NoConnection as e:
        LOGGER.error('Could not connect to %s: %s', url, e)

    # Workaround using requests and HTTP Basic Auth
    if not success:
        LOGGER.debug('Not successful. Trying workaround using requests...')
        try:
            res = requests.get(url, auth=(username, password))
            if res.status_code == 200:
                success = True
        except requests.exceptions.ConnectionError as e:
            LOGGER.error('Could not connect to %s: %s', url, e)

    
    if success:
        LOGGER.info("credentials accepted for user %s",username)
        return username
    else:
        LOGGER.warning("credentials refused for user %s",username)
        return None


'''
Used for authentication via token.
'''
def check_token(token, url):
    
    resp = requests.get(url, headers = {
        "Authorization": "Bearer " + token,
        "Content-type": "application/json"})

    success = (resp.status_code == 200)

    if success:
        LOGGER.info('Token authentication returned HTTP %s' % resp.status_code)
        data = resp.json()
        LOGGER.debug('Data from token endpoint: %s' % data)
        return True, data
    else:
        LOGGER.info('Token authentication failed with HTTP %s' % resp.status_code)
        return False, {}



'''
Used for authentication via token, at the dashboard service created by Sebastian.
'''
def check_token_dashboard(token, dashboard_url):
    
    url = '%s/service_auth?service_auth_token=%s' % (dashboard_url, token)
    LOGGER.debug('Trying to autheticate at "%s..."' % url[:len(url)-12])
    LOGGER.warn('THIS IS VIA HTTP GET AND SHOULD BE CHANGED TO POST!')
    # TODO change to POST as soon as Sebastian changed it!
    resp = requests.get(url)

    LOGGER.debug('Response: HTTP code = %s, Content= "%s"' % (resp.status_code, resp.text))


    if resp.status_code == 200 and resp.text == 'true':
        LOGGER.info('Token authentication was successful!')
        #data = resp.json()
        #LOGGER.debug('Data from token endpoint: %s' % data)
        return True
    else:
        LOGGER.info('Token authentication failed (HTTP code %s): %s'  % (resp.status_code, resp.text))
        return False



class WebDAVAuthenticator(Authenticator):

    # The following attributes can be set in the hub's
    # jupyterhub_config.py:

    # Custom HTML Login form
    custom_html = Unicode(
        "",
        config = True)

    # White list of auth servers where users may authenticate:
    allowed_auth_servers = List([],
        config = True)

    # White list of WebDAV server from which resources may be mounted:
    allowed_webdav_servers = List([],
        config = True)

    # Does the JupyterHub run inside a container?
    #
    # This info can be specified via config (jupyterhub-config.py) or via
    # env-var ("HUB_IS_DOCKERIZED"). The setting from config overrides the
    # env-var. If none are specified, False is assumed.
    #
    # IMPORTANT:
    # Always access this attribute using method "is_hub_running_in_docker()"!
    # (Because the method checks also the env var and edits this attribute).
    hub_is_dockerized = Bool(
        None, allow_none = True,
        config = True)

    # Allow a password to be configured, so we can login without a valid
    # WebDAV account or access to a WebDAV server:
    admin_pw = Unicode(
        None, allow_none = True,
        config = True)

    # Only if JupyterHub runs in a container:
    # Where the userdirectory location will be mounted-to.
    # This dir needs to be used inside the docker-compose file of the hub!!!
    basedir_in_hub_docker = Unicode(
        '/usr/share/userdirectories/',
        config = True)


    '''
    Authenticate method, as needed for any Authenticator class.

    This one uses a token (if present and successful) or WebDAV.

    Please see:
    https://universe-docs.readthedocs.io/en/latest/authenticators.html
    https://jupyterhub.readthedocs.io/en/stable/api/auth.html

    Input:
    The formdata of the login form, as a dict.

    Output:
    This function supports auth_state, so the return is a dict.
    This dict is available to the spawner, so we can place the
    values in the container's environment as variables.
    {
        "name": <username>,
        "auth_state":
            {
                "webdav_mount_password": <webdav_mount_password>,
                ...
            }
    }

    "The Authenticator may return a dict instead, which MUST have a key name
    holding the username, and MAY have two optional keys set: auth_state, a
    dictionary of of auth state that will be persisted; and admin, the admin
    setting value for the user."
    (https://jupyterhub.readthedocs.io/en/stable/api/auth.html)

    :param handler: the current request handler (tornado.web.RequestHandler).
        Not used.
    :param data: The formdata of the login form, as a dict. The default form
        has 'username' and 'password' fields. Should be customized and contain
        more values.
    :return: dict containing username (non-empty string, if authentication
        was successful). The username is None if authentication was not
        successful.
    '''
    @gen.coroutine
    def authenticate(self, handler, data):
        logging.debug("Calling authenticate()...")
        # For some reason, the LOGGER variable is not visible in here,
        # so logging.info(...) has to be used instead of LOGGER.info(...)

        # Get variables from the login form:
        # DEFINITION OF REQUIRED VALUES IN LOGIN POST FORM HERE:
        token = data.get('service_auth_token', '')
        auth_username = data.get('auth_username', data.get('username', ''))
        auth_password = data.get('auth_password', data.get('password', ''))
        auth_url = data.get('auth_url', os.environ['AUTH_URL'])    # TODO: Needed? Only configured?
        token_url = data.get('token_url', os.environ.get('TOKEN_URL', '')) # TODO: Only configured?
        vre_username = data.get('vre_username', auth_username)
        vre_displayname = data.get('vre_displayname', vre_username)
        webdav_mount_username = data.get('webdav_mount_username', '')
        webdav_mount_password = data.get('webdav_mount_password', '')
        webdav_mount_url = data.get('webdav_mount_url', '')
        fileselection_path = data.get('fileselection_path', '')


        # token authentication at the dashboard
        if token != "" and auth_username is not None:
            logging.debug('Trying token authentication at dashboard...')
            success = check_token_dashboard(token, token_url)

            # THIS IS TO TEST TOKEN LOGIN
            if not success and token == self.admin_pw:
                LOGGER.debug('Token authentication with admin password...')
                success = True

            if success:
                logging.info('Token authentication successful for %s' % auth_username)
                validuser = auth_username
                #return auth_username
                # TODO: Add auth_state
                # TODO: Define all those names...
            else:
                logging.info('Token authentication at dashboard not successful!')
                return None

        # token authentication at another service
        # TODO: In future, remove superfluous authentication methods.
        elif token != "":
            logging.debug('Trying token authentication at another service...')
            if token_url is None:
                token_url= TOKEN_URL
                LOGGER.debug('Using the pre-configured URL %s', token_url)

            success, data = check_token(token, token_url)

            # THIS IS TO TEST TOKEN LOGIN
            if not success and token == self.admin_pw:
                LOGGER.debug('Token authentication with admin password...')
                success = True
                import random
                auth_username = random.randint(10000,99999)
                data = {'unity:persistent': auth_username}
                if auth_username == '':
                    LOGGER.info('Token authentication with test token (admin password) not successful, because no username was specified.')
                    return None

            if success:
                username = data["unity:persistent"]
                logging.info('Token authentication successful for %s' % username)
                return username
                # TODO: Add auth_state
                # TODO: Define all those names...
            else:
                logging.info('Token authentication not successful!')
                return None

        # WebDAV username/password authentication
        #logging.info('Authentication using username and password via WebDAV: %s' % auth_url)
        #if not self.is_auth_server_whitelisted(auth_url):
        #    return None
        #
        # WebDAV check here:
        #validuser = check_webdav(auth_username, auth_password, auth_url)

        # Allow a password to be configured, so we can login without a valid
        # WebDAV account or access to a WebDAV server:
        #if validuser is None and auth_password == self.admin_pw:
        #    validuser = auth_username
        #    logging.warning('User %s logged in using the configured admin password!', auth_username)

        if validuser is None:
            logging.warning("Authentication failed for: %s", auth_username)
            return None
            # Otherwise we run into an AttributeError: 'NoneType' object has no attribute 'lower'
            # in "/opt/conda/lib/python3.6/site-packages/jupyterhub/auth.py", line 325, trying "username = username.lower()"

        logging.info("Authentication successful for: %s", auth_username)

        # safety check (QUESTION: In which case does this matter?)
        if "/" in validuser:
            logging.warning("Authentication problem: Username contains slash.")
            return None

        # Also check WebDAV server for whitelist, before passing it
        # on to the spawner:
        if len(webdav_mount_url.strip()) == 0:
            LOGGER.debug('No webdav_mount_url given.')
        else:
            if not self.is_mount_server_whitelisted(webdav_mount_url):
                webdav_mount_url = ''
            else:
                LOGGER.debug('We will pass on: webdav_mount_url=%s (passed the white list check)' % webdav_mount_url)

        # What is the environment here?
        LOGGER.debug('This is the current environment in "authenticate": %s' % os.environ)
        # Contains vars set in docker-compose!
        # Contains vars set in Dockerfile
        # Does not contain the vars set in "c.DockerSpawner.environment" - why not? TODO
        # And: PATH, HOSTNAME (docker id of the hub), 'DEBIAN_FRONTEND': 'noninteractive', 'LANG': 'C.UTF-8', 'HOME': '/root'

        # Return dict for use by spawner
        # See https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#using-auth-state
        auth_state = {
                "name": validuser,
                "auth_state": {
                    "vre_username": vre_username,
                    "vre_displayname": vre_displayname,
                    "webdav_mount_password": webdav_mount_password,
                    "webdav_mount_username": webdav_mount_username,
                    "webdav_mount_url": webdav_mount_url,
                    "fileselection_path": fileselection_path,
                }}
        LOGGER.debug("return auth_state: %s" % auth_state)
        return auth_state


    def is_auth_server_whitelisted(self, auth_url):
        if auth_url not in self.allowed_auth_servers:
            LOGGER.warning("WebDAV server not permitted for authentication: %s", auth_url)
            LOGGER.debug("Only these WebDAV servers are allowed for authentication: %s", self.allowed_auth_servers)
            return False
        LOGGER.debug('Passed whitelist test: %s (for authentication)' % auth_url)
        return True


    def is_mount_server_whitelisted(self, webdav_url):
        if webdav_url not in self.allowed_webdav_servers:
            LOGGER.warning("WebDAV server not permitted for data access: %s", webdav_url)
            LOGGER.debug("Only these WebDAV servers are allowed for data access: %s", self.allowed_webdav_servers)
            return False
        LOGGER.debug('Passed whitelist test: %s (for WebDAV)' % webdav_url)
        return True

    '''
    Find out whether the JupyterHub is running inside a docker container or not.
    This is important for mounting volumes.

    The info must be explicitly given by the operator of JupyterHub (via config
    or env var).

    :return: Boolean.
    '''
    def is_hub_running_in_docker(self):
        # Runs only once, afterwards just returns self.hub_is_dockerized
        # Side effect: May change self.hub_is_dockerized!

        # Use config, if exists:
        # (After the first call, this exists, because the first run sets it!)
        if self.hub_is_dockerized is not None:
            LOGGER.debug('Is hub dockerized? %s', self.hub_is_dockerized)
            return self.hub_is_dockerized

        # If no config is set, use env var:
        try:
            tmp = os.environ['HUB_IS_DOCKERIZED']
            LOGGER.debug('Is hub dockerized? HUB_IS_DOCKERIZED="%s" ("1" or "true" evaluate to True).', tmp)

            if (int(tmp) == 1 or tmp.lower() == 'true'):
                self.hub_is_dockerized = True

            elif (int(tmp) == 0 or tmp.lower() == 'false'):
                self.hub_is_dockerized = False

            else:
                LOGGER.warning('Is hub dockerized? Could not understand HUB_IS_DOCKERIZED="%s", assuming "False"!' % tmp)
                self.hub_is_dockerized = False
        
        # Neither config not env say something:
        except KeyError:
            LOGGER.debug('No environment variable "HUB_IS_DOCKERIZED" found.')
            LOGGER.info('Is hub dockerized? Assuming no, as we found no other information.')
            self.hub_is_dockerized = False

        return self.hub_is_dockerized



    def get_user_dir_path(self, spawner):

        userdir = None

        # Get bind-mount into spawned container
        userdir_on_host = self.get_user_dir_path_on_host(spawner)
        userdir_in_spawned = self.get_user_dir_path_in_spawned(spawner)

        # Stop if no mount:
        if userdir_on_host is None:
            LOGGER.error('************* No volumes mounted into the container.')
            LOGGER.warning('There is no point in using the user directory ' +
                        'if it is not mounted into the spawned container.')
            return None

        # Get dir name (how it's named on the host):
        dirname = os.path.basename(userdir_on_host.rstrip('/'))

        # Get path in hub-container:
        if self.is_hub_running_in_docker():
            userdir_in_hub = self.get_user_dir_path_in_hub(dirname)
            userdir = userdir_in_hub
        else:
            userdir = userdir_on_host

        # All my logging, I will send to you...
        if self.is_hub_running_in_docker():
            LOGGER.info('User directory will be: %s (bind-mounted from %s).',
                userdir_in_hub, userdir_on_host)

            # Some important log messages:
            basedir_in_hub_docker = os.path.dirname(userdir_in_hub.rstrip('/'))
            basedir_on_host = os.path.dirname(userdir_on_host.rstrip('/'))
            needed_mount = "%s:%s" % (basedir_on_host, basedir_in_hub_docker)
            utils.log_first_time(LOGGER, "Hub runs in docker", 
                "Make sure that this bind-mount is in the hub's docker-compose:",
                "%s" % needed_mount)
        else:
            LOGGER.info('User directory will be: %s.', userdir_on_host)

        LOGGER.info('User directory will be availabe in the spawned container as: %s',
            userdir_in_spawned)

        # Return:
        return userdir


    '''
    Return the path of the user directory from the JupyterHub's perspective,
    if the JupyterHub runs inside a container.

    For finding out whether the JupyterHub runs inside a container,
    config or environment variable is used.
    '''
    def get_user_dir_path_in_hub(self, userdirname):

        # If JupyterHub runs inside a container, use the dir where it's mounted:
        userdir_in_hub = os.path.join(self.basedir_in_hub_docker, userdirname)
        
        # Safety check:
        if not os.path.isdir(self.basedir_in_hub_docker):
            LOGGER.error('The directory does not exist: %s (for security reasons, we will not create it here. Make sure it is mounted!' % self.basedir_in_hub_docker)

        return userdir_in_hub

    def get_user_dir_path_in_spawned(self, spawner, index=0):

        # List of bind-mount mountpoints in the spawned container:
        # e.g. ['/home/jovyan/work', '/home/bla/blubb/'].
        #
        # Note: Whether there is a trailing slash seems to depend on user input
        # in the config file.

        LOGGER.debug("All mount points in the spawned container: %s",
            spawner.volume_mount_points)
        return spawner.volume_mount_points[index]


    '''
    Return the path of the user directory on the docker host.

    IMPORTANT:
    If the JupyterHub runs inside a container, this path is NOT the path
    we have to use to create user directories etc.
    '''
    def get_user_dir_path_on_host(self, spawner, index=0):

        # IMPORTANT:
        # We can only use the directory path on the host if the JupyterHub runs
        # directly on the host (i.e. not containerized)! Otherwise we need to
        # use the path of the mount-point (where the dir is bind-mounted to),
        # but INSIDE THE HUB CONTAINER, NOT INSIDE THE SPAWNED CONTAINER,
        # see method "get_user_dir_path_in_hub()".
        #
        # Volume bind-mounts (host to spawned container):
        # See jupyterhub_config.py:
        # c.DockerSpawner.volumes = { '/path/on/host}': '/path/in/spawned/container' }
        #
        # Note: Whether there is a trailing slash seems to depend on user input
        # in the config file.
        
        try:

            # the host directories (as dict) which are bind-mounted, e.g.
            # {'/path/on/host': {'bind': '/path/in/spawned/container', 'mode': 'rw'}}
            LOGGER.debug("On host:  spawner.volume_binds: %s", spawner.volume_binds)

            # list of container directories which are bind-mounted, e.g.
            # ['/path/in/spawned/container']
            LOGGER.debug("In cont.: spawner.volume_mount_points: %s", spawner.volume_mount_points)

            return list(spawner.volume_binds.keys())[index]

        except IndexError as e:
            return None


    '''
    Create the user's directory before the user's container is
    spawned. If intermediate directories don't exist, they are not created,
    for security reasons.

    The directory will then be mounted into the user's container. IMPORTANT:
    This has to configured in jupyterhub_config.py, e.g.:
    c.DockerSpawner.volumes = { '/path/on/host/juser-{username}': '/home/jovyan/work' }

    :param userdir: Full path of the directory.
    '''
    def create_user_directory(self, userdir):

        LOGGER.info("Preparing user's directory (on host or in hub's container): %s", userdir)

        # Create if not exist:
        if os.path.isdir(userdir):
            LOGGER.debug('User directory exists already (owned by %s)!' % os.stat(userdir).st_uid)

        else:
            try:
                LOGGER.debug("Creating dir, as it does not exist.")
                os.mkdir(userdir)
                LOGGER.debug('User directory was created now (owned by %s)!' % os.stat(userdir).st_uid)

            except FileNotFoundError as e:
                LOGGER.error('Could not create user directory (%s): %s', userdir, e)
                LOGGER.debug('Make sure it can be created in the context where JupyterHub is running.')
                superdir = os.path.join(userdir, os.path.pardir)
                LOGGER.debug('Super directory is owned by %s!' % os.stat(superdir).st_uid)               
                raise e # InternalServerError

        return userdir

    '''
    Chown the user's directory before the user's container is
    spawned.

    :param userdir: Full path of the directory.
    :param userdir_owner_id: UID of the directory to be created.
    :param userdir_group_id: GID of the directory to be created.
    '''
    def chown_user_directory(self, userdir, userdir_owner_id, userdir_group_id):

        # Note that in theory, the directory should already be owned by the correct user,
        # as NextCloud or the synchronization process should run as the same UID and have
        # created it.
        #
        # If the directory does not exist yet, it is created by whatever user runs JupyterHub
        # - likely root - so we may have to chown it!
        #
        # In other situations, chowning might be harmful, because whichever process that
        # created it, cannot read/write it anymore. You might want to switch this off!
        # 

        LOGGER.debug("stat before: %s",os.stat(userdir))

        # Check:
        if not os.stat(userdir).st_uid == userdir_owner_id:
            LOGGER.warn("The userdirectory is owned by %s (required: %s), chowning now!" % (os.stat(userdir).st_uid, userdir_owner_id))

        # Execute:
        try:
            LOGGER.debug("chown...")
            os.chown(userdir, userdir_owner_id, userdir_group_id)
        except PermissionError as e:
            LOGGER.error('Chowning not allowed, are you running as the right user?')
            raise e # InternalServerError

        LOGGER.debug("stat after:  %s",os.stat(userdir))
        return userdir

    '''
    Does a few things before a new Container (e.g. Notebook server) is spawned
    by the DockerSpawner:

    * Prepare the directory (to-be-bind-mounted into the container) on the host
    * Mount WebDAV-resource if requested

    This runs in the JupyterHub's container. If JupyterHub does not run inside
    a container, it runs directly on the host. If JupyterHub runs inside a container,
    certain things such as WebDAV mounts do not make sense, because they will not
    be visible on the host, as thus, in the spawned containers!

    Only works if auth_state dict is passed by the Authenticator.
    '''
    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        LOGGER.info('Preparing spawn of container for %s...' % user.name)

        # What is the environment here:
        # TODO Remove this from the printing!
        LOGGER.debug('This is the current environment in "pre_spawn_start": %s' % os.environ)
        # Contains vars set in docker-compose!
        # Contains vars set in Dockerfile
        # Does not contain the vars set in "c.DockerSpawner.environment" - why not? TODO
        # And: PATH, HOSTNAME (docker id of the hub), 'DEBIAN_FRONTEND': 'noninteractive', 'LANG': 'C.UTF-8', 'HOME': '/root'

        # Get userdir name:
        userdir = self.get_user_dir_path(spawner)

        # Set userdir owner id:
        USERDIR_OWNER_ID = os.environ.get('RUN_AS_USER',  None) or USERDIR_OWNER_ID_DEFAULT
        USERDIR_GROUP_ID = os.environ.get('RUN_AS_GROUP', None) or USERDIR_GROUP_ID_DEFAULT
        USERDIR_OWNER_ID = int(USERDIR_OWNER_ID)
        USERDIR_GROUP_ID = int(USERDIR_GROUP_ID)
        LOGGER.info('Will chown to : "%s:%s" (%s, %s)' % (USERDIR_OWNER_ID, USERDIR_GROUP_ID, type(USERDIR_OWNER_ID), type(USERDIR_GROUP_ID)))
            
        # Prepare user directory:
        # This is the directory where the docker spawner will mount the <username>_sync directory!
        # But we create it beforehand so that docker does not create it as root:root
        if userdir is not None:
            LOGGER.info('Preparing user directory...')
            self.create_user_directory(userdir)
            self.chown_user_directory(userdir, USERDIR_OWNER_ID, USERDIR_GROUP_ID)

        # Retrieve variables:
        auth_state = yield user.get_auth_state()

        if not auth_state:
            LOGGER.warning("auth state not availble (performing no more pre-spawn activities).")
            return None
        else:
            LOGGER.debug('auth_state received: "%s"' % auth_state)

        # Create environment vars for the container to-be-spawned:
        # CONTAINER ENVIRONMENT DEFINED HERE:
        spawner.environment['VRE_USERNAME'] = auth_state['vre_username']
        spawner.environment['VRE_DISPLAYNAME'] = auth_state['vre_displayname']
        spawner.environment['WEBDAV_USERNAME'] = auth_state['webdav_mount_username']
        spawner.environment['WEBDAV_PASSWORD'] = auth_state['webdav_mount_password']
        spawner.environment['WEBDAV_URL'] = auth_state['webdav_mount_url']
        spawner.environment['FILESELECTION_PATH'] = auth_state['fileselection_path']

        # Done!
        LOGGER.debug("Finished pre_spawn_start()...")




if __name__ == "__main__":
    # Test with
    # python3 webdavauthenticator.py <username> <password> <url>
    if not len(sys.argv) >= 3:
        print('Not enough args, please call like this: "python 3 webdavauthenticator.py <username> <password> <url>"')
        exit(1)

    logging.basicConfig()

    username=sys.argv[1]
    password=sys.argv[2]
    url=sys.argv[3]

    print('__________________________\nTest WebDAV Authentication...')
    print(check_webdav(username, password, url))

    print('__________________________\nTest creating an Authenticator object...')
    wda = WebDAVAuthenticator()

    print('__________________________\nTest the object...')
    data = dict(
        username = username,
        password = password,
        webdav_url = url,
        webdav_password = password,
        webdav_mountpoint = 'fumptz'
    )

    res = wda.authenticate(None, data)
    if res.done():
        res = res.result()

    print('__________________________\nTest pre-spawn...')
    try:
        os.mkdir('/tmp/mytest/')
        os.mkdir('/tmp/mytest/myuser')
    except Exception as e:
        print(e)
        pass

    import mock
    user = mock.MagicMock()
    user.get_auth_state.return_value = res['auth_state']
    spawner = mock.MagicMock()
    spawner.volume_binds = {'/tmp/mytest/myuser' : {'bind': '/path/in/spawned/container', 'mode': 'rw'}}
    spawner.volume_mount_points = ['/path/in/spawned/container']
    wda.pre_spawn_start(user, spawner)


