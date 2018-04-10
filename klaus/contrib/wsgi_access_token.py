from klaus import make_app
from .app_args import get_args_from_env
from .wsgi import application
from ..access_token import AccessToken

AccessToken(application)
