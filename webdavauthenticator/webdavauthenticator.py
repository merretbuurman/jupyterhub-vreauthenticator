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

from . import synchelper
from . import utils

# Configure logging:
LOGGER = logging.getLogger(__name__)

# Default log level seems to be WARNING and ERROR.
# Adapt log level for this module here:
root = logging.getLogger()
root.setLevel(logging.INFO)

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


# If no url is passed in the login POST form!
AUTH_URL = "https://b2drop.eudat.eu/remote.php/webdav"

# User id and group id for the user's directory. Must match those used in the
# spawned container. Default is 1000:100. In the container they can be changed,
# and are set to the env vars 'NB_UID', 'NB_GID', but those are only available
# inside the container, so we cannot use them here.
# See:
# https://github.com/jupyter/docker-stacks/blob/7a3e968dd21268c4b7a6746458ac34e5c3fc17b9/base-notebook/Dockerfile#L10
# TODO They can be changed in the docker, so we might need to make this
# configurable! Or use post_spawn_stop to get them from the container somehow?
USERDIR_OWNER_ID = 1000
USERDIR_GROUP_ID = 100



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
def check_token(token, data):
    UNITY_URL = "https://unity.eudat-aai.fz-juelich.de:443/oauth2/userinfo" # TODO Move to top

    resp = requests.get(UNITY_URL, headers = {
        "Authorization": "Bearer " + token,
        "Content-type": "application/json"})

    success = (resp.status_code == 200)

    if success:
        # TODO: What is the difference between the data dict returned by the
        # authenticator, and from the unity response. Do we need to keep any of
        # the initial content? Then, maybe merge both before returning?
        LOGGER.debug('Data before: %s' % data)
        data = resp.json()
        LOGGER.debug('Data now   : %s' % data)
        return True, data
    else:
        return False, {}





class WebDAVAuthenticator(Authenticator):

    # The following attributes can be set in the hub's
    # jupyterhub_config.py:

    # Custom HTML Login form
    custom_html = Unicode(
        "",
        config = True)

    # White list of auth servers where users may authenticate:
    allowed_auth_servers = List(
        [WEBDAV_URL],
        config = True)

    # White list of WebDAV server from which resources may be mounted:
    allowed_webdav_servers = List(
        [WEBDAV_URL],
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

    Input: The formdata of the login form, as a dict.

    Mandatory (for authentication):
     * auth_url
     * auth_username
     * auth_password or auth_token

    Optional (for WebDAV mounts from inside the spawned application)
     * webdav_mount_url
     * webdav_mount_username
     * webdav_mount_password


    This function supports auth_state, so the return is a dict.
    This dict is available to the spawner, so we can place the
    values in the container's environment as variables.
    {
        "name": <username>,
        "auth_state":
            {
                "webdav_mount_password": <webdav_mount_password>,
                "webdav_mount_username": <webdav_mount_username>,
                "webdav_mount_url": <webdav_mount_url>,
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
        has 'username' and 'password' fields. Should be customized. See above.
    :return: dict containing username (non-empty string, if authentication
        was successful). The username is None if authentication was not
        successful.
    '''
    @gen.coroutine
    def authenticate(self, handler, data):
        logging.debug("Calling authenticate()...")
        # For some reason, the LOGGER variable is not visible in here,
        # so logging.info(...) has to be used instead of LOGGER.info(...)

        # token authentication
        token = data.get("auth_token","")
        if token != "":
            logging.debug('Trying token authentication...')
            success,data = check_token(token, data)
            if success:
                username = data["unity:persistent"]
                logging.info('Token authentication successful for %s' % username)
                return username
                # TODO: Add auth_state


        # WebDAV username/password authentication
        auth_url = data.get('auth_url', AUTH_URL)
        logging.info('Authentication using username and password via WebDAV: %s' % auth_url)
        if not self.is_auth_server_whitelisted(auth_url):
            return None

        auth_username = data.get('auth_username', data.get('username', ''))
        auth_password = data.get('auth_password', data.get('password', ''))

        # WebDAV check here:
        validuser = check_webdav(auth_username, auth_password, auth_url)

        # Allow a password to be configured, so we can login without a valid
        # WebDAV account or access to a WebDAV server:
        if validuser is None and password == self.admin_pw:
            logging.warning('User %s logged in using the configured admin password!', validuser)
            validuser = username

        if validuser is None:
            logging.warning("Authentication failed for: %s",username)
            return None
            # Otherwise we run into an AttributeError: 'NoneType' object has no attribute 'lower'
            # in "/opt/conda/lib/python3.6/site-packages/jupyterhub/auth.py", line 325, trying "username = username.lower()"

        logging.info("Authentication successful for: %s %s",username, validuser)
        if validuser == username: # isn't this redundant? (QUESTION)

            # safety check (QUESTION: In which case does this matter?)
            if "/" in validuser:
                logging.warning("Authentication failed: Username contains slash.")
                return None

        # Also check WebDAV server for whitelist, before passing it
        # on to the spawner:
        if not self.is_mount_server_whitelisted(webdav_mount_url):
            webdav_mount_url = ''

        # Return dict for use by spawner
        # See https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#using-auth-state
        logging.debug("return auth_state")
        return {"name": validuser,
                "auth_state": {
                    "webdav_mount_password": webdav_mount_password,
                    "webdav_mount_username": webdav_mount_username,
                    "webdav_mount_url": webdav_mount_url,
                }}


    def is_auth_server_whitelisted(self, auth_url):
        if auth_url not in self.allowed_auth_servers:
            LOGGER.warning("WebDAV server not permitted for authentication: %s", auth_url)
            LOGGER.debug("Only these WebDAV servers are allowed for authentication: %s", self.allowed_auth_servers)
            return False
        return True


    def is_mount_server_whitelisted(self, webdav_url):
        if webdav_url not in self.allowed_webdav_servers:
            LOGGER.warning("WebDAV server not permitted for data access: %s", webdav_url)
            LOGGER.debug("Only these WebDAV servers are allowed for data access: %s", self.allowed_webdav_servers)
            return False
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

    @staticmethod
    def get_user_dir_path_in_spawned(spawner, index=0):

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
    @staticmethod
    def get_user_dir_path_on_host(spawner, index=0):

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
    Create (& chown) the user's directory before the user's container is
    spawned. If intermediate directories don't exist, they are not created,
    for security reasons.

    The directory will then be mounted into the user's container. IMPORTANT:
    This has to configured in jupyterhub_config.py, e.g.:
    c.DockerSpawner.volumes = { '/path/on/host/juser-{username}': '/home/jovyan/work' }

    :param userdir: Full path of the directory.
    :param userdir_owner_id: UID of the directory to be created.
    :param userdir_group_id: GID of the directory to be created.
    :param subdir: Name of subdirectory to create.
    '''
    @staticmethod
    def prepare_user_directory(userdir, userdir_owner_id, userdir_group_id, subdir=None):

        # User dir or subdir?
        if subdir is None:
            LOGGER.info("Preparing user's directory (on host or in hub's container): %s", userdir)
        else:
            userdir = os.path.join(userdir, subdir)
            LOGGER.info("Preparing subdirectory in user's directory (on host or in hub's container): %s", userdir)

        # Create if not exist:
        if not os.path.isdir(userdir):
            try:
                LOGGER.debug("Creating dir, as it does not exist.")
                os.mkdir(userdir)
            except FileNotFoundError as e:
                LOGGER.error('Could not create user directory (%s): %s', userdir, e)
                LOGGER.debug('Make sure it can be created in the context where JupyterHub is running.')
                raise e # InternalServerError

        # Chown:
        LOGGER.debug("stat before: %s",os.stat(userdir))
        try:
            LOGGER.debug("chown...")
            os.chown(userdir, userdir_owner_id, userdir_group_id)
        except PermissionError as e:
            LOGGER.error('Chowning not allowed, are you running as the right user?')
            raise e
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

        # Get userdir name:
        userdir = self.get_user_dir_path(spawner)
            
        # Prepare user directory:
        if userdir is not None:
            LOGGER.info('Preparing user directory...')
            userdir = WebDAVAuthenticator.prepare_user_directory(userdir, USERDIR_OWNER_ID, USERDIR_GROUP_ID)

        # Prepare sync subdirectory and synchronization:
        # TODO: Instead, call the synchronization module?!
        if userdir is not None:
            LOGGER.info('Preparing directory for synchronization...')
            syncdir = WebDAVAuthenticator.prepare_user_directory(userdir, USERDIR_OWNER_ID, USERDIR_GROUP_ID, 'sync')
            synchelper.prepare_sync(syncdir, self.basedir_for_textfiles)

        # Retrieve variables:
        auth_state = yield user.get_auth_state()

        if not auth_state:
            LOGGER.warning("auth state not enabled (performing no more pre-spawn activities).")
            return None

        # Create environment vars for the container to-be-spawned:
        # CONTAINER ENVIRONMENT DEFINED HERE:
        spawner.environment['WEBDAV_USERNAME'] = auth_state['webdav_mount_username']
        spawner.environment['WEBDAV_PASSWORD'] = auth_state['webdav_mount_password']
        spawner.environment['WEBDAV_URL'] = auth_state['webdav_mount_url']

        # Done!
        LOGGER.debug("Finished pre_spawn_start()...")




if __name__ == "__main__":
    # Test with
    # python3 webdavauthenticator.py <username> <password>
    if not len(sys.argv) >= 3:
        print('Not enough args, please call like this: "python 3 webdavauthenticator.py <username> <password> <url>"')
        exit(1)

    logging.basicConfig()

    username=sys.argv[1]
    password=sys.argv[2]
    url = WEBDAV_URL
    if len(sys.argv) == 4:
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


