import mechanicalsoup
import warnings
import requests
from urllib.parse import parse_qs, urlparse, urlencode
import xml.etree.ElementTree as ET
import sys
import os
import subprocess

from tornado import gen
from traitlets import Unicode, List, Bool

from jupyterhub.auth import Authenticator
import webdav.client
from urllib.parse import urlparse

import logging


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
WEBDAV_URL = "https://b2drop.eudat.eu/remote.php/webdav"

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
Mount the WebDAV resource using 'mount.davfs' on the
host machine. This is done by the JupyterHub and only
makes sense if JupyterHub is not run inside a container
itself.

If the directory does not exist yet, it is created.

If JupyterHub runs inside a container, the mounted
file system would only be visible inside the Hub's 
container, and not on the host, and thus cannot be 
seen inside the NoteBook container!

Called by pre_spawn_start()
'''
def mount_webdav(webdav_username,webdav_password,userdir_owner_id,userdir_group_id,webdav_url,webdav_fullmountpath):
    LOGGER.debug("Calling mount_webdav()...")

    # Create mount-point:
    if not os.path.isdir(webdav_fullmountpath):
        os.mkdir(webdav_fullmountpath)

    # Execute the mount:
    from subprocess import PIPE as PIPE
    tmp = 'uid=%d,gid=%d,username=%s' % (userdir_owner_id,userdir_group_id,webdav_username)
    cmd_list = ['mount.davfs','-o', tmp, webdav_url, webdav_fullmountpath]
    LOGGER.debug('Mount command: %s', ' '.join(cmd_list))
    p = subprocess.Popen(cmd_list, stdin=PIPE,stdout=PIPE,stderr=PIPE)
    so, se = p.communicate(input=webdav_password.encode("ascii"))

    # Check and return success:
    LOGGER.debug('Mount return code: %s', p.returncode)
    LOGGER.debug('Mount stdout: %s', so)
    LOGGER.debug('Mount stderr: %s', se)
    if p.returncode == 0:
        LOGGER.info('Mounting worked.')
        return True, None
    else:
        se = se.decode('utf-8').replace('\n', ' ') # initially comes as bytes. I assume UTF for converting to string
        LOGGER.error('Mounting failed: %s', se)
        return False, se



'''
Used for authentication via WebDAV.

The username and password are verified against a WebDAV
server, whose URL is passed as arg.

Called by authenticate()

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

Called by authenticate()

'''
def check_token(token):
    UNITY_URL = "https://unity.eudat-aai.fz-juelich.de:443/oauth2/userinfo"

    resp = requests.get(UNITY_URL, headers = {
        "Authorization": "Bearer " + token,
        "Content-type": "application/json"})

    success = (resp.status_code == 200)

    if success:
        data = resp.json()
        return True, data
    else:
        return False, {}


'''
Used to prepare the directory where WebDAV data will be mounted 
before a new Notebook is spawned.

Called by pre_spawn_start(), and in case of token
authentication also by authenticate().

A directory is created and its owner is set to 1000:100.

:param validuser: Username as string.
:param userdir: Full path of the directory.
:return: Tuple: The full directory name, the UID, and the GID of
    of the directory owner.
'''
def prep_dir(validuser, userdir, userdir_owner_id, userdir_group_id):
    LOGGER.debug("Calling prep_dir()...")
    LOGGER.debug("userdir: %s",userdir)

    if not os.path.isdir(userdir):
        LOGGER.debug("mkdir...")
        try:
            os.mkdir(userdir)
        except FileNotFoundError as e:
            LOGGER.error('Could not create user directory (%s): %s', userdir, e)
            LOGGER.debug('Make sure it can be created in the context where JupyterHub is running.')
            raise e # InternalServerError

    LOGGER.debug("stat before: %s",os.stat(userdir))
    LOGGER.debug("chown...")
    os.chown(userdir,userdir_owner_id,userdir_group_id)
    LOGGER.debug("stat after: %s",os.stat(userdir))

    return None

class WebDAVAuthenticator(Authenticator):

    # The following attributes can be set in the hub's
    # jupyterhub_config.py:

    # Custom HTML Login form
    custom_html = Unicode(
        "",
        config = True)

    # White list of WebDAV server from which resources may be mounted:
    allowed_webdav_servers = List(
        [WEBDAV_URL],
        config = True)

    # Should the user's WebDAV resource be mounted by the Hub before spawn?
    do_webdav_mount = Bool(
        False,
        config = True)

    # Does the JupyterHub run inside a container? This can also be set by an
    # environment variable (because then it can easily be included in the Hub's
    # docker file). The config setting overrides the env var. If none are
    # specified, False is assumed.
    hub_is_dockerized_conf = Bool(
        None, allow_none = True,
        config = True)

    # Allow a password to be configured, so we can login without a valid
    # WebDAV account or access to a WebDAV server:
    admin_pw =  = Unicode(
        None, allow_none = True,
        config = True)

    '''
    Authenticate method, as needed for any Authenticator class.

    This one uses a token (if present and successful) or WebDAV.

    Please see:
    https://universe-docs.readthedocs.io/en/latest/authenticators.html
    https://jupyterhub.readthedocs.io/en/stable/api/auth.html

    This function supports auth_state, so the return is a dict:
    {
        "name": <username>,
        "auth_state":
            {
                "webdav_password": <webdav_password>,
                "webdav_username": <webdav_username>,
                "webdav_url": <webdav_url>,
                "webdav_mountpoint": <webdav_mountpoint>
            }
    }

    "The Authenticator may return a dict instead, which MUST have a key name
    holding the username, and MAY have two optional keys set: auth_state, a
    dictionary of of auth state that will be persisted; and admin, the admin
    setting value for the user."
    (https://jupyterhub.readthedocs.io/en/stable/api/auth.html)

    :param handler: the current request handler (tornado.web.RequestHandler)
    :param data: The formdata of the login form, as a dict. The default form
        has 'username' and 'password' fields.
        Should also have 'webdav_url', 'webdav_password', 'webdav_mountpoint'.
    :return: dict containing username (non-empty string, if authentication
        was successful). The username is None if authentication was not
        successful.
    '''
    @gen.coroutine
    def authenticate(self, handler, data):
        logging.debug("Calling authenticate()...")
        # For some reason, the LOGGER variable is not visible in here,
        # so logging.info(...) has to be used instead of LOGGER.info(...)

        token = data.get("token","") # "" if missing

        # token authentication
        if token != "":
            logging.debug('Trying token authentication...')
            success,data = check_token(token)

            if success:
                username = data["unity:persistent"]
                logging.info('Token authentication successful for %s' % username)

                # Prepare user's directory:
                basedir = "/mnt/data/jupyterhub-user/" # TODO: define somewhere else!
                logging.debug('Default location for user directories: %s', basedir)
                userdir = os.path.join(basedir,"jupyterhub-user-" + username)
                logging.info('Preparing directory: %s')
                prep_dir(username, userdir, USERDIR_OWNER_ID, USERDIR_GROUP_ID)
                return username

        # username/password authentication
        logging.info('Authentication using username and password (via WebDAV)...')
        webdav_url = data.get('webdav_url', WEBDAV_URL)
        logging.info("WebDAV server: %s",webdav_url)

        if not self.is_server_whitelisted(webdav_url):
            return None

        password = data.get("password","") # "" if missing
        username = data['username']
        webdav_username = data.get('webdav_username',username)
        webdav_password = data.get('webdav_password',password)
        webdav_mountpoint = data.get('webdav_mountpoint',"WebDAV")

        # WebDAV check here:
        validuser = check_webdav(username,password,webdav_url)

        # Allow a password to be configured, so we can login without a valid
        # WebDAV account or access to a WebDAV server:
        if validuser is None and password == self.admin_pw:
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
                logging.warn("Authentication failed: Username contains slash.")
                return None

            # if not mount, set path to ""
            if not self.do_webdav_mount:
                logging.debug('Mounting not requested.')
                webdav_mountpoint = ""

        # Return dict
        logging.debug("return auth_state")
        return {"name": validuser,
                "auth_state": {
                    "webdav_password": webdav_password,
                    "webdav_username": webdav_username,
                    "webdav_url": webdav_url,
                    "webdav_mountpoint": webdav_mountpoint,
                }}


    def is_server_whitelisted(self, webdav_url):
        if webdav_url not in self.allowed_webdav_servers:
            logging.warning("WebDAV server not permitted: %s", webdav_url)
            logging.debug("Only these WebDAV servers are allowed: %s", self.allowed_webdav_servers)
            return False
        return True

    '''
    Find out whether the JupyterHub spawning the containers is running inside
    a docker container, or not. This is important for mounting volumes.

    The information must be explicitly given my the operators of the JupyterHub.
    This can be done in two ways:

    1. The info can be found from either a environment variable
    ('HUB_IS_DOCKERIZED'), which can be passed from the docker-compose.yml in
    case it is a containerized JuypterHub. The values 1 or '1' or 'treu' or 
    'True' or 'TRUE' all evaluate to True.

    2. It can also be passed as a config item in the jupyterhub_config.py. This
    takes precedence over the environment variable.

    Note that if JupyterHub is dockerized, the directory that is used for 
    creating user directories must be bind-mounted to here:
    /usr/share/userdirectories/

    :return: Boolean.
    '''
    def is_hub_running_in_docker(self):
        hub_dockerized = False
        try:
            tmp = os.environ['HUB_IS_DOCKERIZED']
            LOGGER.debug('Is hub dockerized? Env var says: %s ("1" or "true" evaluate to True).', tmp)
            if (int(tmp)  == 1 or tmp.lower() == 'true'):
                hub_dockerized = True
        except KeyError:
            LOGGER.debug('Is hub dockerized? No environment variable "HUB_IS_DOCKERIZED" found.')

        LOGGER.debug('Is hub dockerized? Config says: %s', self.hub_is_dockerized_conf)
        if self.hub_is_dockerized_conf is not None:
            hub_dockerized = self.hub_is_dockerized_conf
            LOGGER.debug('Is hub dockerized? Config overrides: %s', hub_dockerized)
        else:
            LOGGER.debug('Is hub dockerized? Keeping this value: %s', hub_dockerized)

        return hub_dockerized



    '''
    Does a few things before a new Container (e.g. Notebook server) is spawned
    by the DockerSpawner:

    * Prepare the directory (to-be-bind-mounted into the container) on the host


    This runs in the JupyterHub's container. If JupyterHub does not run inside
    a container, it runs directly on the host. If JupyterHub runs inside a container,
    certain things such as WebDAV mounts do not make sense, because they will not
    be visible on the host, as thus, in the spawned containers!

    Only works if auth_state dict is passed by the Authenticator.
    '''
    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        LOGGER.debug("Calling pre_spawn_start()...")
        LOGGER.debug("pre_spawn_start for user %s",user.name)

        # Write the WebDAV token to the users' environment variables
        auth_state = yield user.get_auth_state()

        if not auth_state:
            LOGGER.warning("auth state not enabled (performing no pre-spawn activities).")
            # auth_state not enabled
            return

        LOGGER.debug("spawner.escaped_name: %s", spawner.escaped_name)

        # Volume bind-mounts
        # See jupyterhub_config.py
        # c.DockerSpawner.volumes = { '/scratch/vre/jupyter_diva/jupyter-user-{username}': '/home/jovyan/work' }
        LOGGER.debug("On host:  spawner.volume_binds: %s", spawner.volume_binds) # the host directories (as dict) which are bind-mounted, e.g. {'/home/dkrz/k204208/STACKS/spawnertest/nginxtest/foodata/jupyterhub-user-eddy': {'bind': '/home/jovyan/work', 'mode': 'rw'}}
        LOGGER.debug("In cont.: spawner.volume_mount_points: %s", spawner.volume_mount_points) # list of container directores which are bind-mounted, e.g. ['/home/jovyan/work']

        # Where user dirs go on the host:
        userdir_on_host = list(spawner.volume_binds.keys())[0]

        # IMPORTANT:
        # We can only use the userdir_on_host if the JupyterHub runs directly on
        # the host! Otherwise we need to use the bind-mounted directory (where
        # the userdir is mounted to)!

        # First find out if JupyterHub runs in container:
        hub_dockerized = self.is_hub_running_in_docker()

        # If JupyterHub runs inside a container, use the dir where it's mounted:
        userdir = None
        if hub_dockerized:
            userdir = '/usr/share/userdirectories/'
            LOGGER.info('Hub is dockerized. Make sure that the directory %s is mounted to %s.', userdir_on_host, userdir)
            LOGGER.info('User directory will be in: %s (bind-mounted %s).', userdir, userdir_on_host)
        else:
            userdir = userdir_on_host
            LOGGER.info('Hub is not dockerized. User directory will be in: %s', userdir)

        # Prepare mount dir:
        LOGGER.info("Creating user's directory (on host or in hub's container): %s", userdir)
        uid, gid = USERDIR_OWNER_ID, USERDIR_GROUP_ID
        prep_dir(user.name, userdir, uid, gid)

        # Get WebDAV config from POST form:
        webdav_mountpoint = auth_state['webdav_mountpoint']
        webdav_username = auth_state['webdav_username']
        webdav_password = auth_state['webdav_password']
        webdav_url = auth_state['webdav_url']

        # Do the mount (if requested)
        if webdav_mountpoint == "":
            LOGGER.info('No WebDAV mount requested.')
        else:
            LOGGER.info('WebDAV mount:')
            webdav_fullmountpath = os.path.join(userdir, webdav_mountpoint)
            mount_ok, err_msg = mount_webdav(webdav_username,
                         webdav_password,
                         uid, gid,
                         webdav_url,
                         webdav_fullmountpath)

        # Create environment vars for the container to-be-spawned:
        LOGGER.debug("setting env. variable: %s",user)
        #spawner.environment['WEBDAV_USERNAME'] = auth_state['webdav_username']
        spawner.environment['WEBDAV_USERNAME'] = user.name
        spawner.environment['WEBDAV_PASSWORD'] = webdav_password
        spawner.environment['WEBDAV_URL'] = webdav_url
        spawner.environment['WEBDAV_MOUNT'] = webdav_mountpoint # deprecated. for backwards compatibility.
        spawner.environment['WEBDAV_MOUNTPOINT'] = webdav_mountpoint
        spawner.environment['WEBDAV_SUCCESS'] = str(mount_ok).lower()
        spawner.environment['PRE_SPAWN_ERRORS'] = err_msg or ''
        LOGGER.debug("Finished pre_spawn_start()...")



if __name__ == "__main__":
    # Test with
    # python3 webdavauthenticator.py <username> <password>
    username=sys.argv[1]
    password=sys.argv[2]

    print(check_webdav(username,password))

    WebDAVAuth = WebDAVAuthenticator()
