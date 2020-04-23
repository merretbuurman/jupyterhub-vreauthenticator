import requests
import os
import tornado.gen
import traitlets
import jupyterhub.auth
import logging


VERSION = '20200422'

# Logging for this module: Default is info, can be configured using a env var.
LOGGER = logging.getLogger(__name__)
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
# TODO Why in addition?
#formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(name)s: %(message)s')
#handler = logging.StreamHandler(sys.stdout)
#handler.setFormatter(formatter)
#root.addHandler(handler)



'''
Used for authentication via token, at the dashboard service created by Sebastian.
'''
def check_token_at_dashboard(token, dashboard_url):

    url = '%s/service_auth' % dashboard_url
    post_data = {'service_auth_token': token}
    LOGGER.debug('Trying to authenticate at "%s..." (via POST)' % url[:len(url)-12])
    try:
        resp = requests.post(url, data = post_data)
    except requests.exceptions.ConnectionError as e: #requests.exceptions.ConnectionError: HTTPSConnectionPool(host='sdc-test.argo.grnet.gr', port=443): Max retries exceeded with url: /service_auth (Caused by NewConnectionError('<urllib3.connection.VerifiedHTTPSConnection object at 0x7fad7bc5aeb8>: Failed to establish a new connection: [Errno 113] No route to host',))
        LOGGER.error('Caught exception: %s' % e)
        LOGGER.info('Token authentication failed (no HTTP code), but exception: %s'  % e)
        return False

    LOGGER.debug('Response: HTTP code = %s, Content= "%s"' % (resp.status_code, resp.text))

    if resp.status_code == 200 and resp.text == 'true':
        LOGGER.info('Token authentication was successful!')
        return True
    else:
        LOGGER.info('Token authentication failed (HTTP code %s): %s'  % (resp.status_code, resp.text))
        return False



class VREAuthenticator(jupyterhub.auth.Authenticator):

    # The following attributes can be set in the hub's
    # jupyterhub_config.py:

    # Custom HTML Login form
    custom_html = traitlets.Unicode('',
        config = True)

    # Authentication server to be used:
    auth_url = traitlets.Unicode('',
        config = True)

    # White list of auth servers where users may authenticate:
    allowed_auth_servers = traitlets.List([],
        config = True)

    # OPTIONAL:
    # Tell the service whether the user directories are mounted.
    # If not, no user directory preparation is done!
    userdirs_are_mounted = traitlets.Bool(False,
        config = True)

    # Where the userdirectory location will be mounted-to.
    # This dir needs to be used inside the docker-compose file of the hub!!!
    basedir_in_containerized_hub = traitlets.Unicode('',
        config = True)

    # OPTIONAL:
    # Allow an admin password to be configured, so we can login without
    # using the authentication service (for testing, etc.):
    admin_pw = traitlets.Unicode(None,
        config = True,
        allow_none = True)

    # OPTIONAL:
    # File selector server to be used:
    #fileselector_url = traitlets.Unicode(None,
    #    config = True,
    #    allow_none = True)

    # OPTIONAL:
    # See c.JupyterHub.base_url in JupyterHub URL Scheme docs
    # https://test-jupyterhub.readthedocs.io/en/latest/reference/urls.html
    #base_url = traitlets.Unicode('',
    #    config = True)

    # OPTIONAL:
    # User id for the user's directory. Must match the uid used to run the
    # process in the container, otherwise the process cannot read/write into
    # the user directory.
    #
    # For JupyterNotebooks, default is 1000. Can be changed by passing the
    # env var 'NB_UID' to the container (which we do in jupyterhub_config.py).
    # See:
    # https://github.com/jupyter/docker-stacks/blob/7a3e968dd21268c4b7a6746458ac34e5c3fc17b9/base-notebook/Dockerfile#L10
    userdir_user_id = traitlets.Integer(1000,
        config = True)

    # OPTIONAL:
    # Group id for the user's directory. Must match the gid used to run the
    # process in the container, otherwise the process cannot read/write into
    # the user directory.
    #
    # For JupyterNotebooks, default is 100. Can be changed by passing the
    # env var 'NB_GID' to the container (which we do in jupyterhub_config.py).
    # See:
    # https://github.com/jupyter/docker-stacks/blob/7a3e968dd21268c4b7a6746458ac34e5c3fc17b9/base-notebook/Dockerfile#L10
    userdir_group_id = traitlets.Integer(100,
        config = True)


    @tornado.gen.coroutine
    def authenticate(self, handler, data):
        LOGGER.debug("Calling authenticate()...")

        # Variables from the login form:
        auth_username = data.get('auth_username', data.get('username', ''))
        auth_url = data.get('auth_url', self.auth_url).strip('/')
        service_auth_token = data.get('service_auth_token', data.get('password', ''))
        vre_username = data.get('vre_username', auth_username)
        vre_displayname = data.get('vre_displayname', vre_username)
        fileselection_path = data.get('fileselection_path', '')


        # Authentication

        if len(auth_username) == 0 or auth_username is None:
            LOGGER.error('Username missing!')
            return None

        if len(service_auth_token) == 0 or service_auth_token is None:
            LOGGER.error('Token missing!')
            return None

        if not self.is_auth_server_whitelisted(auth_url):
            return False

        LOGGER.debug('Trying token authentication at dashboard...')
        success = check_token_at_dashboard(service_auth_token, auth_url)

        if success:
            LOGGER.info('Token authentication successful for %s' % auth_username)

        elif service_auth_token == self.admin_pw:
            LOGGER.info('Token authentication at dashboard failed for %s' % auth_username)
            LOGGER.debug('Authentication with admin password successful for %s' % auth_username)
            success = True

        else:
            LOGGER.info('Token authentication at dashboard failed for %s' % auth_username)
            return None

        # safety check (QUESTION: In which case does this matter?)
        if "/" in auth_username:
            LOGGER.warning("Authentication problem: Username contains slash.")
            return None

        LOGGER.info("Authentication successful for: %s", auth_username)


        # What is the environment here?
        LOGGER.debug('This is the current environment in "authenticate" (in the hub): %s' % os.environ)
        # Contains vars set in docker-compose!
        # Contains vars set in Dockerfile
        # Does not contain the vars set in "c.DockerSpawner.environment" - why not? TODO
        # And: PATH, HOSTNAME (docker id of the hub), 'DEBIAN_FRONTEND': 'noninteractive', 'LANG': 'C.UTF-8', 'HOME': '/root'

        # Return dict for use by spawner
        # See https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#using-auth-state
        auth_state = {
                "name": auth_username,
                "auth_state": {
                    "vre_username": vre_username,
                    "vre_displayname": vre_displayname,
                    "fileselection_path": fileselection_path,
                    "service_auth_token": service_auth_token
                }}
        LOGGER.debug("return auth_state: %s" % auth_state)
        return auth_state


    def is_auth_server_whitelisted(self, auth_url):
        if auth_url not in self.allowed_auth_servers:
            LOGGER.warning("URL not permitted for authentication: %s", auth_url)
            LOGGER.debug("Only these URLs are allowed for authentication: %s", self.allowed_auth_servers)
            return False
        LOGGER.debug('Passed whitelist test: %s (for authentication)' % auth_url)

        if str.startswith(auth_url, 'http://'):
            LOGGER.warning('Authentication URL is plain http!')

        return True


    def get_user_dir_path(self, spawner):

        userdir_path_on_host = None
        userdir_path_in_hub = None
        userdir_path_in_spawned = None
        userdir_name = None

        # 1/2
        # Location bind-mount into spawned container

        try:

            # the host directories (as dict) which are bind-mounted, e.g.
            # {'/path/on/host': {'bind': '/path/in/spawned/container', 'mode': 'rw'}}
            LOGGER.debug("On host:  spawner.volume_binds: %s", spawner.volume_binds)

            # list of container directories which are bind-mounted, e.g.
            # ['/path/in/spawned/container']
            LOGGER.debug("In cont.: spawner.volume_mount_points: %s", spawner.volume_mount_points)

            index = 0
            userdir_path_on_host = list(spawner.volume_binds.keys())[index]
            userdir_path_in_spawned = spawner.volume_mount_points[index]

        # Stop if no mount:
        except IndexError as e:
            LOGGER.error('Did not find volume: %s' % e)
            LOGGER.error('************* No volumes mounted into the container.')
            LOGGER.warning('There is no point in using the user directory ' +
                           'if it is not mounted into the spawned container.')
            return None

        # TODO TEST IF THIS CAN HAPPEN
        if len(userdir_path_on_host)==0 or len(userdir_path_in_spawned)==0:
            LOGGER.error('Problem with volume mounts, either host or container is empty: %s:%s' % 
                         (userdir_path_on_host, userdir_path_in_spawned))
            return None

        # Get dir name (how it's named on the host):
        userdir_name = os.path.basename(userdir_path_on_host.rstrip('/'))

        # 2/2
        # Location inside the hub container:

        basedir_path_in_hub = self.basedir_in_containerized_hub
        userdir_path_in_hub = os.path.join(basedir_path_in_hub, userdir_name)

        # Safety check:
        if not os.path.isdir(basedir_path_in_hub):
            LOGGER.error('The directory does not exist: %s (for security reasons, '+
                         'we will not create it here. Make sure it is mounted!' % basedir_path_in_hub)
            return None
        
        # Logging
        LOGGER.info('User directory will be: %s (bind-mounted from %s).',
            userdir_path_in_hub, userdir_path_on_host)
        LOGGER.info('User directory will be availabe in the spawned container as: %s',
            userdir_path_in_spawned)

        # Return:
        return userdir_path_in_hub


    def create_user_directory(self, userdir_path):
        LOGGER.info("Preparing user's directory (in hub's container): %s", userdir_path)

        # Create if not exist:
        if os.path.isdir(userdir_path):
            LOGGER.debug('User directory exists already (owned by %s)!' % os.stat(userdir_path).st_uid)

        else:
            try:
                LOGGER.debug("Creating dir, as it does not exist.")
                os.mkdir(userdir_path)
                LOGGER.debug('User directory was created now (owned by %s)!' % os.stat(userdir_path).st_uid)

            except FileNotFoundError as e:
                LOGGER.error('Could not create user directory (%s): %s', userdir_path, e)
                LOGGER.debug('Make sure it can be created in the context where JupyterHub is running.')
                superdir = os.path.join(userdir, os.path.pardir)
                LOGGER.debug('Super directory is owned by %s!' % os.stat(userdir_path).st_uid)               
                raise e

        return userdir_path


    def chown_user_directory(self, userdir_path, userdir_user_id, userdir_group_id):

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

        LOGGER.debug("stat before: %s", os.stat(userdir_path))

        # Check:
        if not os.stat(userdir_path).st_uid == userdir_user_id:
            LOGGER.warn("The userdirectory is owned by %s (required: %s), chowning now!" % (os.stat(userdir_path).st_uid, userdir_user_id))

        # Execute:
        try:
            LOGGER.debug("chown...")
            os.chown(userdir_path, userdir_user_id, userdir_group_id)
        except PermissionError as e:
            LOGGER.error('Chowning not allowed, are you running as the right user?')
            raise e

        LOGGER.debug("stat after:  %s", os.stat(userdir_path))
        return userdir_path

    def prepare_user_directory(self, spawner):

        # Get userdir name:
        userdir = self.get_user_dir_path(spawner)

        # Set userdir owner id:
        LOGGER.info('Will chown to : "%s:%s"' % (self.userdir_user_id, self.userdir_group_id))
    
        # Prepare user directory:
        # This is the directory where the docker spawner will mount the <username>_sync directory!
        # But we create it beforehand so that docker does not create it as root:root
        if userdir is not None:
            LOGGER.info('Preparing user directory...')
            self.create_user_directory(userdir)
            self.chown_user_directory(userdir, self.userdir_user_id, self.userdir_group_id)

    @tornado.gen.coroutine
    def pre_spawn_start(self, user, spawner):
        LOGGER.info('Preparing spawn of container for %s...' % user.name)

        # What is the environment here:
        # TODO Remove this from the printing!
        LOGGER.debug('This is the current environment in "pre_spawn_start": %s' % os.environ)
        # Contains vars set in docker-compose!
        # Contains vars set in Dockerfile
        # Does not contain the vars set in "c.DockerSpawner.environment" - why not? TODO
        # And: PATH, HOSTNAME (docker id of the hub), 'DEBIAN_FRONTEND': 'noninteractive', 'LANG': 'C.UTF-8', 'HOME': '/root'

        # Prepare user directory
        if self.userdirs_are_mounted:
            self.prepare_user_directory(spawner)
        else:
            LOGGER.debug('Userdirectories are not mounted.')

        # Retrieve variables:
        auth_state = yield user.get_auth_state()

        if not auth_state:
            LOGGER.warning("Auth state not available (performing no more pre-spawn activities).")
            return None
        else:
            LOGGER.debug('auth_state received: "%s"' % auth_state)

        # Create environment vars for the container to-be-spawned:
        # CONTAINER ENVIRONMENT DEFINED HERE:
        spawner.environment['VRE_USERNAME'] = auth_state['vre_username']
        spawner.environment['VRE_DISPLAYNAME'] = auth_state['vre_displayname']
        spawner.environment['FILESELECTION_PATH'] = auth_state['fileselection_path']
        spawner.environment['SERVICE_AUTH_TOKEN'] = auth_state['service_auth_token']
        spawner.environment['JUPYTERHUB_TOKEN'] = auth_state['service_auth_token']
        spawner.environment['FOO_MAP'] = auth_state['service_auth_token']
        # Added by JupyterHub:
        # JUPYTERHUB_USER (which is the same as VRE_USERNAME)
        # and others
        #
        #spawner.environment['FILESELECTOR_URL'] = self.fileselector_url
        #spawner.environment['BASE_URL'] = self.base_url
        # Those variables that do not change per user are set in jupyterhub_config.py,
        # see this line: "c.DockerSpawner.environment = container_env"

        # Log this:
        LOGGER.debug('This is the environment to be sent to the container: %s' % spawner.environment)
        LOGGER.debug("Finished pre_spawn_start()...")



if __name__ == "__main__":
    # Test with
    # python3 vreauthenticator.py <username> <token> <url>

    import sys
    if not len(sys.argv) >= 3:
        print('Not enough args, please call like this: "python 3 vreauthenticator.py <username> <token> <url>"')
        exit(1)

    logging.basicConfig()

    username=sys.argv[1]
    token=sys.argv[2]
    url=sys.argv[3]

    print('__________________________\nTest Authentication...')

    print(check_token_at_dashboard(token, url))

    print('__________________________\nTest creating an Authenticator object...')

    wda = VREAuthenticator()

    print('__________________________\nTest the object...')

    handler = None
    data = dict(
        username = username,
        password = password,
        webdav_url = url,
        webdav_password = password,
        webdav_mountpoint = 'fumptz'
    )

    res = wda.authenticate(handler, data)
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


