import logging
LOGGER = logging.getLogger(__name__)


PATH_SYNC_FILE = '/srv/jupyterhub/please_sync_these.txt' # TODO!!!

def prepare_sync(syncdir):
    # TODO: Instead, call the synchronization module?!
    LOGGER.debug('SYNC: Writing info into %s, hoping someone will read it' % PATH_SYNC_FILE)
    with open(PATH_SYNC_FILE, "a") as syncfile:
        syncfile.write(syncdir+'\n')
