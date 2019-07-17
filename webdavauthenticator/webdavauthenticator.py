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



WEBDAV_URL = "https://b2drop.eudat.eu/remote.php/webdav"

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
def mount_webdav(webdav_username,webdav_password,userdir_owner_id,userdir_group_id,webdav_url,webdav_fullmount):
    LOGGER.debug("Calling mount_webdav()...")

    if not os.path.isdir(webdav_fullmount):
        os.mkdir(webdav_fullmount)

    try:
        p = subprocess.run(['mount.davfs','-o','uid=%d,gid=%d,username=%s' % (userdir_owner_id,userdir_group_id,webdav_username),webdav_url,webdav_fullmount],
                       stdout=subprocess.PIPE,input=webdav_password.encode("ascii"))
    except subprocess.CalledProcessError as e:
        LOGGER.error('Mounting failed: %s', e)



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

    success = resp.status_code == 200

    if success:
        data = resp.json()
        return True, data
    else:
        return False, {}


'''
Used to prepare the directory where WebDAV data will be mounted 
before a new Notebook is spawned.

Called by pre_spawn_start(), and in case of token
authentication also by  authenticate().

A directory is created and its owner is set to 1000:100.

:param validuser: Username as string.
:param userdir: Optional. Full path of the directory. If not
    given, the default is used.
:return: Tuple: The full directory name, the UID, and the GID of
    of the directory owner.
'''
def prep_dir(validuser,userdir = None):
    basedir = "/mnt/data/jupyterhub-user/"
    userdir_owner_id = 1000
    userdir_group_id = 100

    if userdir == None:
        # warning username might be escaped
        userdir = os.path.join(basedir,"jupyterhub-user-" + validuser)

    print("userdir",userdir,file=sys.stderr)
    print("dir before",os.listdir(basedir),file=sys.stderr)

    if not os.path.isdir(userdir):
        print("create",userdir,file=sys.stderr)
        os.mkdir(userdir)

    print("dir after",os.listdir(basedir),file=sys.stderr)
    print("stat before",os.stat(userdir),file=sys.stderr)
    os.chown(userdir,userdir_owner_id,userdir_group_id)
    print("stat after",os.stat(userdir),file=sys.stderr)

    return userdir,userdir_owner_id,userdir_group_id

class WebDAVAuthenticator(Authenticator):

    custom_html = Unicode(
        "",
        config = True)

    allowed_webdav_servers = List(
        [WEBDAV_URL],
        config = True)

    do_webdav_mount = Bool(
        False,
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
                "webdav_mount": <webdav_mount>
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
                logging.debug('Preparing directory...')
                prep_dir(username)
                return username

        # username/password authentication
        logging.info('Authentication using username and password (via WebDAV)...')
        password = data.get("password","") # "" if missing
        username = data['username']
        webdav_url = data.get('webdav_url', WEBDAV_URL)
        webdav_username = data.get('webdav_username',username)
        webdav_password = data.get('webdav_password',password)
        webdav_mount = data.get('webdav_mount',"WebDAV")

        # Server allowed?
        logging.info("WebDAV server: %s",webdav_url)
        if webdav_url not in self.allowed_webdav_servers:
            logging.warning("WebDAV server not permitted: %s", webdav_url)
            logging.debug("Only these WebDAV servers are allowed: %s", self.allowed_webdav_servers)
            return None

        # WebDAV check here:
        validuser = check_webdav(username,password,webdav_url)
        if validuser is None:
            logging.warning("Authentication failed for: %s",username)
            return None
            # Otherwise we run into an AttributeError: 'NoneType' object has no attribute 'lower'
            # in "/opt/conda/lib/python3.6/site-packages/jupyterhub/auth.py", line 325, trying "username = username.lower()"

        logging.info("Authentication successful for: %s %s",username, validuser)
        if validuser == username:

            # safety check
            if "/" in validuser:
                logging.warn("Authentication failed: Username contains slash.")
                return None

            # if not mount, set path to ""
            if not self.do_webdav_mount:
                logging.debug('Mounting not requested.')
                webdav_mount = ""

        # Return dict
        logging.debug("return auth_state")
        return {"name": validuser,
                "auth_state": {
                    "webdav_password": webdav_password,
                    "webdav_username": webdav_username,
                    "webdav_url": webdav_url,
                    "webdav_mount": webdav_mount,
                }}

    '''
    Does a few things before a new Container (e.g. Notebook server) is spawned
    by the DockerSpawner.

    This runs in the JupyterHub's container. If JupyterHub does not run inside
    a container, it runs directly on the host.

    Only works if auth_state dict is passed by the Authenticator.
    '''
    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        LOGGER.debug("Calling pre_spawn_start()...")
        LOGGER.debug("pre_spawn_start for user %s",user.name)

        # Write the WebDAV token to the users' environment variables
        auth_state = yield user.get_auth_state()

        if not auth_state:
            LOGGER.warning("auth state not enabled (doing nothing).")
            # auth_state not enabled
            return

        LOGGER.debug("spawner.escaped_name: %s", spawner.escaped_name)
        LOGGER.debug("spawner.volume_mount_points: %s", spawner.volume_mount_points)
        LOGGER.debug("spawner.volume_binds: %s", spawner.volume_binds)

        userdir = list(spawner.volume_binds.keys())[0]
        dummy,userdir_owner_id,userdir_group_id = prep_dir(user.name,userdir = userdir)

        webdav_mount = auth_state['webdav_mount']
        webdav_username = auth_state['webdav_username']
        webdav_password = auth_state['webdav_password']
        webdav_url = auth_state['webdav_url']

        if webdav_mount != "":
            webdav_fullmount = os.path.join(userdir,webdav_mount)
            mount_webdav(webdav_username,
                         webdav_password,
                         userdir_owner_id,
                         userdir_group_id,
                         webdav_url,
                         webdav_fullmount)

        LOGGER.debug("setting env. variable: %s",user)
        #spawner.environment['WEBDAV_USERNAME'] = auth_state['webdav_username']
        spawner.environment['WEBDAV_USERNAME'] = user.name
        spawner.environment['WEBDAV_PASSWORD'] = webdav_password
        spawner.environment['WEBDAV_URL'] = webdav_url
        spawner.environment['WEBDAV_MOUNT'] = webdav_mount



if __name__ == "__main__":
    # Test with
    # python3 webdavauthenticator.py <username> <password>
    username=sys.argv[1]
    password=sys.argv[2]

    print(check_webdav(username,password))

    WebDAVAuth = WebDAVAuthenticator()
