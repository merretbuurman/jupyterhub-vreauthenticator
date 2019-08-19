import logging
LOGGER = logging.getLogger(__name__)

PATH_WEBDAV_INFO = '/srv/jupyterhub/please_mount_these.txt'


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
def mount_webdav(webdav_username, webdav_password, userdir_owner_id, userdir_group_id, webdav_url, webdav_fullmountpath):
    LOGGER.debug("Calling mount_webdav()...")

    # Create mount-point:
    if not os.path.isdir(webdav_fullmountpath):
        LOGGER.debug("Creating dir, as it does not exist.") # TODO: if it was mounted into the spawned container, it surely exists!
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
Meant for dockerized JupyterHubs that cannot do it themselves. Some daemon
or service on the host mounts the WebDAV data (via mount.davfs) onto the
host's FS from where it has to be bind-mounted into the container.

Notes:

* Need to deploy that service!
* Need to bind.mount the info file at /srv/jupyterhub/please_mount_these.txt
* Need to set c.WebDAVAuthenticator.external_webdav_mount = True
'''
def prepare_external_mount(webdav_username, webdav_password, webdav_url):
    LOGGER.warning("Host is responsible for WebDAV mount...")
    LOGGER.debug('Writing the WebDAV info into %s, hoping someone will read it' % PATH_WEBDAV_INFO)
    infoline = "%s %s %s" % (webdav_username, webdav_password, webdav_url)
    LOGGER.debug("Append line: %s", infoline)
    with open(PATH_WEBDAV_INFO, "a") as myfile:
        myfile.write(infoline+'\n')