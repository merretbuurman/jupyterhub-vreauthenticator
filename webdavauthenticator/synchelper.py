import os
import logging
LOGGER = logging.getLogger(__name__)


SYNC_FILE = 'please_sync_these.txt'

def prepare_sync(syncdir, basedir):
    # TODO: Instead, call the synchronization module?!
    path = os.path.join(basedir, SYNC_FILE)
    LOGGER.debug('SYNC: Writing info into %s, hoping someone will read it' % path)

    try:
        with open(path, "a") as syncfile:
            syncfile.write(syncdir+'\n')
    except FileNotFoundError as e:
        LOGGER.error('Cannot write into %s, please make sure it is there and writable!' % path)
        raise e
