import config

def setup_virtualchain( impl = None ):
    if impl is not None:
        config.set_implementation( impl )