import os
import logging
DEBUG = False
if os.environ.get("ZONEFILEMANAGE_DEBUG") == "1":
    DEBUG = True

def get_logger(name="ZONEFILEMANAGE"):
    """
    Get virtualchain's logger
    """

    level = logging.CRITICAL
    if DEBUG:
        logging.disable(logging.NOTSET)
        level = logging.DEBUG

    if name is None:
        name = "<unknown>"
        level = logging.CRITICAL

    log = logging.getLogger(name=name)
    log.setLevel(level)
    console = logging.StreamHandler()
    console.setLevel(level)
    file_handler = logging.FileHandler("test.log")
    file_handler.setLevel(level)
    log_format = ('[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d] (' + str(
        os.getpid()) + '.%(thread)d) %(message)s' if DEBUG else '%(message)s')
    formatter = logging.Formatter(log_format)
    console.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    log.propagate = False

    if len(log.handlers) > 0:
        for i in xrange(0, len(log.handlers)):
            log.handlers.pop(0)

    log.addHandler(console)
    log.addHandler(file_handler)
    return log

