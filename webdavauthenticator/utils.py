
FIRST_LOG = True

def log_first_time(LOGGER, *msgs):

    if not FIRST_LOG:
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
