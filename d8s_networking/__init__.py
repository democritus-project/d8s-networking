try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import PackageNotFoundError, version  #type: ignore

try:
    __version__ = version('democritus_networking')
except PackageNotFoundError:
    message = 'Unable to find a version number for "democritus_networking". This likely means the library was not installed properly. Please re-install it and, if the problem persists, raise an issue here: https://github.com/democritus-project/democritus-networking/issues.'
    print(message)

__author__ = '''Floyd Hightower'''
__email__ = 'floyd.hightower27@gmail.com'

from .networking import *