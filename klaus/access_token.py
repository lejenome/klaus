import os
import json
from base64 import b64encode
from datetime import datetime, timedelta
from collections import namedtuple
from functools import partial
from cryptography.fernet import Fernet, InvalidToken
from flask import url_for, redirect, current_app, request, abort
from flask_principal import (
    Principal, Identity, AnonymousIdentity, identity_changed, identity_loaded,
    Permission
)


RepoNeed = namedtuple('repo', ['method', 'value'])
ViewRepoNeed = partial(RepoNeed, 'view')
ListRepoNeed = partial(RepoNeed, 'list', None)
ListRepoPermission = partial(Permission, ListRepoNeed())


class ViewRepoPermission(Permission):
    def __init__(self, repo):
        need = ViewRepoNeed(repo)
        super(ViewRepoPermission, self).__init__(need)


def _invitation_view():
    identity_changed.send(current_app._get_current_object(),
                          identity=AnonymousIdentity())
    token = request.values.get("token", None)
    if not token:
        return redirect(url_for("repo_list"))
    try:
        secret = b64encode(current_app.secret_key[:32].encode())
        aes = Fernet(secret)
        data = aes.decrypt(token.encode()).decode()
        data = json.loads(data)
        invt_timeout = datetime.strptime(
            data["invitation_timeout"], "%Y-%m-%dT%H:%M:%S.%f")
        if invt_timeout < datetime.utcnow():
            raise TimeoutError()
        ident = json.dumps({
            "repos": data["repos"],
        })
        identity_changed.send(current_app._get_current_object(),
                              identity=Identity(ident))
        return redirect('/')
    except TimeoutError:
        return "Expired Access Token", 403
    except (KeyError, ValueError, json.JSONDecodeError, InvalidToken):
        return "Invalid Access Token", 403


def _on_identity_loaded(sender, identity):
    if not isinstance(identity.id, str):
        return
    data = json.loads(identity.id)
    for repo in data['repos']:
        identity.provides.add(ViewRepoNeed(repo))
    identity.provides.add(ListRepoNeed())


def _on_before_request_access_token():
    if request.endpoint == "repo_list":
        # TODO: only list repos with view permission
        # repos = [repo for repo in current_app.repos.values()
        #          if ViewRepoPermission(repo.name).can()]
        permission = ListRepoPermission()
        if not permission.can():
            abort(403)
    elif "repo" in request.view_args:
        # or request.endpoint not in ("robots_txt", "static") and "repo" in :
        permission = ViewRepoPermission(request.view_args["repo"])
        if not permission.can():
            abort(403)


def generate_access_token(secret_key, repos,
                          invitation_ttl=timedelta(weeks=1)):
    secret = b64encode(secret_key[:32].encode())
    invitation_timeout = datetime.now() + invitation_ttl
    token = json.dumps({
        "repos": repos,
        "invitation_timeout": invitation_timeout.isoformat(),
    })
    aes = Fernet(secret)
    token = aes.encrypt(token.encode()).decode()
    print("Access Token", repos, ":", token)


def AccessToken(app):
    try:
        if not app.secret_key:
            app.secret_key = os.environ['FLASK_SECRET_KEY']
    except KeyError:
        print("app.secret_key or FLASK_SECRET_KEY environ variable should be defined")
    # add _require_access_token decorator into /<repo>/* urls

    app.add_url_rule("/invitation", "invitation", _invitation_view)
    # A hack to move /invitation url rule before /<repo> url rule
    invt_rule = app.url_map._rules.pop()
    app.url_map._rules.insert(0, invt_rule)
    app.url_map._remap = True
    app.url_map.update()

    Principal(app)
    app.before_request(_on_before_request_access_token)
    identity_loaded.connect_via(app)(_on_identity_loaded)
    generate_access_token(app.secret_key, list(app.repos.keys()))


if __name__ == '__main__':
    import sys
    try:
        secret_key = os.environ['FLASK_SECRET_KEY']
    except KeyError:
        print("FLASK_SECRET_KEY environ variable souble be defined")
        sys.exit()
    secret_key = os.environ.get('FLASK_SECRET_KEY')
    repos = sys.argv[1:]
    generate_access_token(secret_key, repos)
