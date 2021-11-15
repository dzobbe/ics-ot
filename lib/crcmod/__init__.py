try:
    from lib.crcmod.crcmod import *
    from lib.crcmod import predefined
except ImportError:
    # Make this backward compatible
    from lib.crcmod import *
    from lib.crcmod import predefined
__doc__ = crcmod.__doc__
