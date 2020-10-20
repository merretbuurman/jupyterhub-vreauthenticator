import requests
import os
import tornado.gen
import traitlets
import jupyterhub.auth
import logging


VERSION = '20200428'

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

LOGGER.info('Starting... (vreauthenticator.py of %s)' % VERSION)

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
Used for authentication via token, at the dashboard service created by
Sebastian Mieruch, AWI.
'''
def check_token_at_dashboard(token, dashboard_url):
    LOGGER.info('Attempting token authentication...')

    url = '%s/service_auth' % dashboard_url
    post_data = {'service_auth_token': token}
    LOGGER.debug('Trying to authenticate at "%s..." (via POST)' % url[:len(url)-12])
    
    try:
        resp = requests.post(url, data = post_data)

    except requests.exceptions.ConnectionError as e: #requests.exceptions.ConnectionError: HTTPSConnectionPool(host='vre.seadatanet.org', port=443): Max retries exceeded with url: /service_auth (Caused by NewConnectionError('<urllib3.connection.VerifiedHTTPSConnection object at 0x7fad7bc5aeb8>: Failed to establish a new connection: [Errno 113] No route to host',))
        LOGGER.error('Caught exception (possibly the auth service is down): %s' % e)
        LOGGER.info('Token authentication failed (no HTTP code), exception: %s'  % e)
        return False

    except requests.exceptions.RequestException as e:
        LOGGER.error('Caught unexpected exception: %s' % e)
        LOGGER.info('Token authentication failed (no HTTP code), exception: %s'  % e)
        return False

    LOGGER.debug('Response: HTTP code = %s, Content= "%s"' % (resp.status_code, resp.text))

    if resp.status_code == 200 and resp.text == 'true':
        LOGGER.debug('Token authentication was successful!')
        return True
    else:
        LOGGER.info('Token authentication failed (HTTP code %s): %s'  % (resp.status_code, resp.text))
        return False


'''
Custom Authenticator.
https://github.com/jupyterhub/jupyterhub/blob/master/jupyterhub/auth.py


'''
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

    # Where the base directory (directory containing the user directories)
    # is on the host. Needed to find the correct bind-mount.
    basedir_on_host = traitlets.Unicode('',
        config = True)

    # OPTIONAL:
    # Allow an admin password to be configured, so we can login without
    # using the authentication service (for testing, etc.):
    admin_pw = traitlets.Unicode(None,
        config = True,
        allow_none = True)

    # User id for the user's directory. Must match the uid used to run the
    # process in the container, otherwise the process cannot read/write into
    # the user directory.
    #
    # For JupyterNotebooks, default is 1000. Can be changed by passing the
    # env var 'NB_UID' to the container (which we do in jupyterhub_config.py).
    # See:
    # https://github.com/jupyter/docker-stacks/blob/7a3e968dd21268c4b7a6746458ac34e5c3fc17b9/base-notebook/Dockerfile#L10
    userdir_user_id = traitlets.Integer(9999,
        config = True,
        allow_none = False)

    # Group id for the user's directory. Must match the gid used to run the
    # process in the container, otherwise the process cannot read/write into
    # the user directory.
    #
    # For JupyterNotebooks, default is 100. Can be changed by passing the
    # env var 'NB_GID' to the container (which we do in jupyterhub_config.py).
    # See:
    # https://github.com/jupyter/docker-stacks/blob/7a3e968dd21268c4b7a6746458ac34e5c3fc17b9/base-notebook/Dockerfile#L10
    userdir_group_id = traitlets.Integer(9999,
        config = True,
        allow_none = False)

    @tornado.gen.coroutine
    def authenticate(self, handler, data):
        LOGGER.debug("Calling authenticate()...")

        # Variables from the login form:
        vre_username = data.get('vre_username', data.get('auth_username', data.get('username', '')))
        auth_username = data.get('auth_username', data.get('vre_username', data.get('username', '')))
        auth_url = self.auth_url.strip('/')
        service_auth_token = data.get('service_auth_token', data.get('password', ''))
        vre_displayname = data.get('vre_displayname', vre_username)

        # Verify variables:

        if len(auth_username) == 0 or auth_username is None:
            LOGGER.error('Username missing!')
            return None

        if len(service_auth_token) == 0 or service_auth_token is None:
            LOGGER.error('Token missing!')
            return None

        if not self.is_auth_server_whitelisted(auth_url):
            LOGGER.warning("URL not permitted for authentication: %s", auth_url)
            return False

        # Authentication

        success = check_token_at_dashboard(service_auth_token, auth_url)

        if success:
            LOGGER.info('Token authentication successful for %s' % auth_username)

        elif service_auth_token == self.admin_pw:
            LOGGER.info('Token authentication at dashboard failed for %s' % auth_username)
            LOGGER.info('Authentication with admin password successful for %s' % auth_username)
            success = True

        else:
            LOGGER.info('Token authentication at dashboard failed for %s' % auth_username)
            return None

        # safety check (QUESTION: In which case does this matter?)
        if "/" in auth_username:
            LOGGER.warning("Authentication problem: Username contains slash.")
            return None

        LOGGER.info("Authentication successful for: %s", auth_username)

        # Log the environment here:
        self.print_environment_authenticate()

        # Return dict for use by spawner
        # See https://jupyterhub.readthedocs.io/en/stable/reference/authenticators.html#using-auth-state
        auth_state = {
                "name": auth_username,
                "auth_state": {
                    "vre_username": vre_username,
                    "vre_displayname": vre_displayname,
                    "service_auth_token": service_auth_token
                }}
        LOGGER.debug("return auth_state: %s" % auth_state)
        return auth_state


    def print_environment_authenticate(self):
        LOGGER.debug('This is the current environment in "authenticate" (in the hub): %s' % os.environ)
        # Contains vars set in docker-compose!
        # And: PATH, HOSTNAME (docker id of the hub), 'DEBIAN_FRONTEND': 'noninteractive', 'LANG': 'C.UTF-8', 'HOME': '/root'


    def is_auth_server_whitelisted(self, auth_url):
        
        if auth_url not in self.allowed_auth_servers:
            LOGGER.debug("Only these URLs are allowed for authentication: %s", self.allowed_auth_servers)
            return False
        
        LOGGER.debug('Passed whitelist test: %s (for authentication)' % auth_url)

        if str.startswith(auth_url, 'http://'):
            LOGGER.warning('Authentication URL is plain http!')

        return True

    '''
    Get the full absolute path of the user's directory (which is mounted into
    the spawned container), as it is called inside the hub container.

    Mounted to hub:
      /storage/bla/blub/nextcloud_all/              : /usr/share/userdirectories
      /storage/bla/blub/nextcloud_all/johndoe/files : /usr/share/userdirectories/johndoe/files
    
    Mounted to spawned:
      /storage/bla/blub/nextcloud_all/johndoe/files : /nextcloud

    This returns:
      /storage/bla/blub/nextcloud_all/johndoe/files

    '''
    def get_full_userdir_path_in_hub(self, spawner):

        userdir_path_on_host = None
        userdir_path_in_hub = None
        userdir_path_in_spawned = None

        # Find the mount which has the expected base dir:
        LOGGER.debug('Finding the bind-mount that contains the user-data:')
        all_mounted_host_dirs = list(spawner.volume_binds.keys())
        found = False
        for this_host_dir in all_mounted_host_dirs:
            if self.basedir_on_host in this_host_dir:
                LOGGER.debug('It is this one: %s:%s' % (this_host_dir, spawner.volume_binds[this_host_dir]))
                userdir_path_on_host = this_host_dir
                userdir_path_in_spawned = spawner.volume_binds[this_host_dir]
                found = True

        # Treat missing mount:
        if not found:
            LOGGER.error('Missing mount: No user directory is mounted into the spawned containers.')
            LOGGER.info('The user directory should be inside: %s' % self.basedir_on_host)
            LOGGER.info('Either the "basedir_on_host" setting is wrong, or the "c.DockerSpawner.volume" (in jupyterhub_config.py).')
            LOGGER.info('These exist: spawner.volume_binds: %s', spawner.volume_binds)
            raise FileNotFoundError('Missing mount: No userdir (starting with "%s") was mounted into spawned container!' % self.basedir_on_host)

        # Get dir name (how it's named on the host):
        # Split into common part and user-specific part (e.g. "johndoe", "johndoe/files"):
        common_part_host = self.basedir_on_host.rstrip('/')+'/'
        individual_part = userdir_path_on_host.split(common_part_host)[1]
        individual_part_list = individual_part.strip('/').split('/')

        # Get dir name (how it's named in the hub container):
        common_part_hub = self.basedir_in_containerized_hub
        userdir_path_in_hub = os.path.join(common_part_hub, individual_part)
        
        # Logging
        LOGGER.info('User directory will be: %s (bind-mounted from %s).',
            userdir_path_in_hub, userdir_path_on_host)
        LOGGER.info('User directory will be availabe in the spawned container as: %s',
            userdir_path_in_spawned)

        # Return:
        return userdir_path_in_hub

    '''
    Create directory, if not exists yet.

    :param dir_in_hub: Full absolute path of directory to be created, inside hub container.
    :return: None
    :raise: FileNotFoundError
    '''
    def create_dir(self, dir_in_hub):

        if os.path.isdir(dir_in_hub):
            LOGGER.debug('%s exists already (owned by %s)!' % os.stat(dir_in_hub).st_uid)
            return

        try:
            LOGGER.info("Creating directory: %s (did not exist)" % dir_in_hub)
            os.mkdir(dir_in_hub)
            LOGGER.debug('Directory was created now (owned by %s)!' % os.stat(dir_in_hub).st_uid)
            return

        except FileNotFoundError as e:
            LOGGER.error('Could not create user directory (%s): %s', dir_in_hub, e)
            LOGGER.debug('Make sure it can be created in the context where JupyterHub is running.')
            superdir = os.path.join(dir_in_hub, os.path.pardir)
            LOGGER.debug('Super directory is owned by %s!' % os.stat(dir_in_hub).st_uid)               
            raise e


    '''
    Change uid and gid of directory.

    :param dir_in_hub: Full absolute path of directory to be created, inside hub container.
    :param userdir_user_id: Integer uid that the directory will have.
    :param userdir_group_id: Integer gid that the directory will have.
    :return: None
    :raise: PermissionError

    Note:

        # Note that in theory, the directory should already be owned by the correct user,
        # as either NextCloud is mounted directly and should in theory run as the same uid:gid,
        # (or at least a matching/suitable uid:gid combination), OR or the synchronization tool
        # should have created it and it should run as the same uid:gid.
        #
        # If the directory does not exist yet, it is created by whatever user runs JupyterHub
        # - likely root - so we have to chown it!
        #
        # In other situations, chowning might be harmful, because whichever process that
        # created it, cannot read/write it anymore. You might want to switch this off!

    '''
    def chown_dir(self, dir_in_hub, userdir_user_id, userdir_group_id):
        # TODO: Which uid:gid combination is acceptible, which should we change?
        # Note: If the directory exists, we leave it unchanged anyway.
        # If it is created by us, it is probably root:root, and needs to be changed.

        uid_gid = '%s:%s' % (userdir_user_id, userdir_group_id)
        current_uid = os.stat(dir_in_hub).st_uid
        current_gid = os.stat(dir_in_hub).st_gid

        if (current_uid == userdir_user_id and current_gid == userdir_group_id):
            LOGGER.info('Directory is already owned by %s.' % uid_gid)
            return

        LOGGER.warn("The directory is owned by %s:%s (required: %s), chowning now!" %
            (current_uid, current_gid, uid_gid))

        try:
            os.chown(dir_in_hub, userdir_user_id, userdir_group_id)
        except PermissionError as e:
            LOGGER.error('Chowning not allowed, are you running as the right user?')
            raise e




    def prepare_user_directory(self, spawner):

        # Some checks before we go:
        self.some_checks(spawner)

        # Print the host directories (as dict) which are bind-mounted, e.g.
        # {'/path/on/host': {'bind': '/path/in/spawned/container', 'mode': 'rw'}}
        LOGGER.debug("On host:  spawner.volume_binds: %s", spawner.volume_binds)

        # Print list of container directories which are bind-mounted, e.g.
        # ['/path/in/spawned/container']
        LOGGER.debug("In cont.: spawner.volume_mount_points: %s", spawner.volume_mount_points)

        # Get userdir name:
        userdir_path_in_hub = self.get_full_userdir_path_in_hub(spawner)

        # Nothing to do if it exists:
        if os.path.isdir(userdir_path_in_hub):
            LOGGER.info('User directory exists already (owned by %s)!' % 
                os.stat(userdir_path_in_hub).st_uid)
            LOGGER.debug('Not chowning existing directory.')
            return

        # Split into common part (e.g. "/usr/share/userdirectories/") and
        # user-specific part (e.g. "johndoe/files")
        common_part = self.basedir_in_containerized_hub.rstrip('/')+'/'
        individual_part = userdir_path_in_hub.split(common_part)[1]
        subdirs = individual_part.strip('/').split('/')

        # If simple directory, e.g. "johndoe":
        if len(subdirs) == 1:
            LOGGER.debug('Only one directory hierarchy to be created: %s' % subdirs)
            self.create_dir(userdir_path_in_hub)
            self.chown_dir(userdir_path_in_hub, self.userdir_user_id, self.userdir_group_id)

        # If nested, e.g. "johndoe/files":
        # Create the hierarchy levels one by one:
        if len(subdirs) > 1:
            LOGGER.debug('Several directory hierarchies to be created: %s' % subdirs)
            to_be_created = common_part.rstrip('/')
            for level in subdirs:
                to_be_created += '/'+level
                self.create_dir(to_be_created)
                self.chown_dir(to_be_created, self.userdir_user_id, self.userdir_group_id)


    def some_checks(self, spawner):

        # Check if attributes are set:
        if self.userdir_user_id is None: # WIP remove if cannot set none
            raise ValueError('Need to set userdir_user_id!')

        if self.userdir_group_id is None:
            raise ValueError('Need to set userdir_user_id!')

        # Check if any volumes mounted at all:
        if len(spawner.volume_mount_points) == 0:
            LOGGER.error('************* No volumes mounted into the container.')
            LOGGER.warning('There is no point in using the user directory ' +
                           'if it is not mounted into the spawned container.')
            raise ValueError('Missing mount: No volumes mounted into the container!')

        # Safety check:
        if not os.path.isdir(self.basedir_in_containerized_hub):
            LOGGER.error('The directory does not exist: %s (for security reasons, '+
                         'we will not create it here. Make sure it is mounted!' % 
                         self.basedir_in_containerized_hub)
            raise ValueError('Missing directory: The directory does not exist in the '+
                'hub container: %s' % self.basedir_in_containerized_hub)


    def print_pre_spawn_environment(self):
        # What is the environment at this point:

        LOGGER.debug('This is the current environment in "pre_spawn_start": %s' % os.environ)

        # Contains:
        # * vars set in docker-compose
        # * vars set in Dockerfile of the hub
        # * 'PATH', 'HOSTNAME' (docker id of the hub), 'DEBIAN_FRONTEND': 'noninteractive',
        #   'LANG': 'C.UTF-8', 'HOME': '/root'
        #
        # Does not contain:
        #  * The vars set in "c.DockerSpawner.environment", because this is in the hub'd
        #    container, not the spawned container!



    def print_spawner_environment(self, spawner):
        LOGGER.debug('This is the environment to be sent to the container: %s' % spawner.environment)
        # Added by JupyterHub:
        # JUPYTERHUB_USER (which is the same as VRE_USERNAME), and others


    @tornado.gen.coroutine
    def pre_spawn_start(self, user, spawner):
        LOGGER.info('Preparing spawn of container for %s...' % user.name)

        # Environment:
        self.print_pre_spawn_environment()

        # Prepare user directory.
        # This directory will be mounted into the spawned container. We create it (and
        # chown it to the required uid:gid) beforehand so that docker does not create
        # it as root:root
        if self.userdirs_are_mounted:
            self.prepare_user_directory(spawner)
        else:
            LOGGER.info('Userdirectories are not mounted.')

        # Retrieve variables:
        auth_state = yield user.get_auth_state()

        if not auth_state:
            LOGGER.warning("Auth state not available (performing no more pre-spawn activities).")
            return None
        else:
            LOGGER.debug('auth_state received: "%s"' % auth_state)

        # Create environment vars for the container to-be-spawned:
        spawner.environment['VRE_USERNAME']       = auth_state['vre_username']
        spawner.environment['VRE_DISPLAYNAME']    = auth_state['vre_displayname']
        spawner.environment['SERVICE_AUTH_TOKEN'] = auth_state['service_auth_token']
        spawner.environment['JUPYTERHUB_TOKEN']   = auth_state['service_auth_token'] # TODO Ask Leo to use SERVICE_AUTH_TOKEN

        # Environment:
        self.print_spawner_environment(spawner)

        LOGGER.debug("Finished pre_spawn_start()...")

