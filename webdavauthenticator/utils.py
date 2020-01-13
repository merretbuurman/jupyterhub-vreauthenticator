
FIRST_LOG = True
LOGGED_TIMES = 0

# Note that this can only be used once in the
# code, as the counter is global!

def log_first_time(LOGGER, *msgs):

    global LOGGED_TIMES
    global FIRST_LOG
    LOGGED_TIMES = LOGGED_TIMES+1

    if not FIRST_LOG:
        #LOGGER.debug('Logged this x times: %s' % LOGGED_TIMES)
        return

    # Which character to use?
    c = '*'
    
    # Max length of message:
    l = 0
    for msg in msgs:
        l = max(l, len(msg))

    # First and last time:
    firstlast = (l*c)+(8*c)
    
    # Log:
    LOGGER.warning(firstlast)
    for msg in msgs:
        filled = msg.ljust(l)
        LOGGER.warning(3*c+' '+filled+' '+3*c)
    LOGGER.warning(firstlast)

    FIRST_LOG = False
