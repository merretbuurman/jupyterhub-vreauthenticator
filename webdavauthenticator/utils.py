

def log_first_time(LOGGER, *msgs):
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