import os
import json
from base64 import b64encode
from datetime import datetime, timedelta
from collections import namedtuple
from functools import partial
from cryptography.fernet import Fernet, InvalidToken
from flask import (
    url_for, redirect, current_app, request, abort, render_template
)
from flask.views import View
from flask_principal import (
    Principal, Identity, AnonymousIdentity, identity_changed, identity_loaded,
    Permission, RoleNeed
)


AdminPermission = partial(Permission, RoleNeed('admin'))
UserPermission = partial(Permission, RoleNeed('user'))
RepoNeed = namedtuple('repo', ['method', 'value'])
ViewRepoNeed = partial(RepoNeed, 'view')
ListRepoNeed = partial(RepoNeed, 'list', None)
ListRepoPermission = partial(Permission, ListRepoNeed())


class ViewRepoPermission(Permission):
    def __init__(self, repo):
        need = ViewRepoNeed(repo)
        super(ViewRepoPermission, self).__init__(need)


class _InvitationView(View):
    methods = ['GET', 'POST']

    def dispatch_request(self):
        token = request.values.get("token", None)
        if token is None:
            return self.access_form()
        elif token == '':
            self.clear_access()
            return redirect(url_for("invitation"))
        else:
            return self.try_access(token)

    def clear_access(self):
        identity_changed.send(current_app._get_current_object(),
                              identity=AnonymousIdentity())

    def try_access(self, token):
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
                "role": data.get("role", "user"),
            })
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(ident))
            return redirect(url_for("repo_list"))
        except TimeoutError:
            self.clear_access()
            # return "Expired Access Token", 403
            return redirect(url_for("invitation"))
        except (KeyError, ValueError, json.JSONDecodeError, InvalidToken):
            self.clear_access()
            # return "Invalid Access Token", 403
            return redirect(url_for("invitation"))

    def access_form(self):
        admin_permission = AdminPermission()
        user_permission = UserPermission()
        if admin_permission.can():
            repos_list = request.form.getlist("repos")
            print(repos_list)
            repos_list = [repo.strip() for repo in repos_list if repo.strip()]
            repos = {repo: repo in repos_list
                     for repo in current_app.repos.keys()}
            if repos_list:
                access_token = generate_access_token(current_app.secret_key,
                                                     repos_list)
            else:
                access_token = None
            return render_template('invitation_generate.html',
                                   access_token=access_token,
                                   repos=repos,
                                   base_href=None)
        elif user_permission.can():
            allowed_repos = [repo for repo in current_app.repos.keys()
                             if ViewRepoPermission(repo).can()]
            return render_template('invitation_status.html',
                                   repos=allowed_repos,
                                   base_href=None)
        else:
            return render_template('invitation_index.html',
                                   base_href=None)


def _on_identity_loaded(sender, identity):
    if not isinstance(identity.id, str):
        return
    data = json.loads(identity.id)
    if data.get('role', None) == 'admin':
        identity.provides.add(RoleNeed('admin'))
    else:
        identity.provides.add(RoleNeed('user'))
        for repo in data['repos']:
            identity.provides.add(ViewRepoNeed(repo))
    identity.provides.add(ListRepoNeed())


def _on_before_request_access_token():
    if AdminPermission().can():
        return
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


def generate_access_token(secret_key, repos=[], admin=False,
                          invitation_ttl=timedelta(weeks=1)):
    secret = b64encode(secret_key[:32].encode())
    invitation_timeout = datetime.now() + invitation_ttl
    token = json.dumps({
        "repos": repos,
        "role": "admin" if admin else "user",
        "invitation_timeout": invitation_timeout.isoformat(),
    })
    aes = Fernet(secret)
    token = aes.encrypt(token.encode()).decode()
    return token


def AccessToken(app):
    try:
        if not app.secret_key:
            app.secret_key = os.environ['FLASK_SECRET_KEY']
    except KeyError:
        print("app.secret_key or FLASK_SECRET_KEY environ variable should be defined")
    # add _require_access_token decorator into /<repo>/* urls

    app.add_url_rule("/invitation", "invitation", view_func=_InvitationView.as_view('invitation'))
    # A hack to move /invitation url rule before /<repo> url rule
    invt_rule = app.url_map._rules.pop()
    app.url_map._rules.insert(0, invt_rule)
    app.url_map._remap = True
    app.url_map.update()

    Principal(app)
    app.before_request(_on_before_request_access_token)
    identity_loaded.connect_via(app)(_on_identity_loaded)


if __name__ == '__main__':
    import sys
    try:
        secret_key = os.environ['FLASK_SECRET_KEY']
    except KeyError:
        print("FLASK_SECRET_KEY environ variable souble be defined")
        sys.exit()
    secret_key = os.environ.get('FLASK_SECRET_KEY')
    repos = sys.argv[1:]
    token = generate_access_token(secret_key, admin=True,
                                  invitation_ttl=timedelta(weeks=12))
    print("Admin Access Token:", token)
