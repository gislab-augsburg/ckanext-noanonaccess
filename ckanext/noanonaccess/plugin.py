import logging
import re
from flask import current_app

import ckan.plugins as plugins
from ckan.plugins import toolkit as tk
from ckan.plugins.toolkit import config

# helpers to build URLs correctly when redirect_path is a path/absolute URL
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

log = logging.getLogger(__name__)

# endpoints we never want to echo back into came_from (prevents loops)
_DEFAULT_DISALLOW_PATHS = (
    '/user/sso',
    '/user/sso_login',
    '/user/login',
    '/user/_logout',
    '/user/logged_out',
    '/user/logged_out_redirect',
    '/user/reset',
    '/user/locked',
)


class NoanonaccessPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IAuthenticator
    def identify(self):
        try:
            is_anonoumous_user = tk.current_user.is_anonymous
        except Exception:
            # for before ckan v2.10.x
            from ckan.views import _identify_user_default

            _identify_user_default()
            if getattr(tk.c, "user", False):
                is_anonoumous_user = False
            else:
                is_anonoumous_user = True

        # if not anonymous user then only check blocked paths
        if not is_anonoumous_user:

            # set current path and redirect path specified in the environment variable
            current_path = tk.request.path
            redirect_path_config = config.get("ckanext.noanonaccess.redirect_path", [])
            if not redirect_path_config:
                redirect_path = "user.login"  # route name
            else:
                site_url = config.get("ckan.site_url")
                redirect_path = site_url + redirect_path_config  # absolute URL

            # block regex path list specified in the environment variable
            blocked_access = False
            blocked_paths = config.get("ckanext.noanonaccess.blocked_paths", [])
            if blocked_paths:
                blocked_paths = blocked_paths.split(" ")

            for path in blocked_paths:
                if re.match(path, current_path):
                    blocked_access = True
                    break

            # block access for all users
            if blocked_access:
                return self._redirect_with_optional_came_from(redirect_path)

            return

        # if anonymous user then apply restrictions
        current_path = tk.request.path

        def _get_blueprint_and_view_function():
            if hasattr(tk.request, "blueprint"):
                if current_path is not None:
                    route = current_app.url_map.bind("").match(current_path)
                    endpoint = route[0]
                    if "." not in endpoint:
                        return endpoint
                    blueprint_name, view_function_name = endpoint.split(".", 1)
                    return "%s.%s" % (blueprint_name, view_function_name)
                else:
                    return ""
            else:
                # Backwards compatibility for CKAN < 2.9.x (Pylons routes)
                pylons_mapper = config.get("routes.map", "")
                match = pylons_mapper.routematch(current_path)
                if match:
                    # Extract the controller and action from the matched route
                    controller = match[0]["controller"]
                    action = match[0]["action"]
                    name = match[1].name or controller
                    return "%s.%s" % (name, action)
                else:
                    return ""

        current_blueprint = _get_blueprint_and_view_function()

        # check if the blueprint route is in the allowed list
        allowed_blueprint = [
            "static",  # static files
            "user.login",  # login page
            "user.register",  # register page
            "user.logout",  # logout page
            "user.logged_out_page",  # logged out page redirect
            "user.request_reset",  # request reset page
            "user.perform_reset",  # perform reset page
            "util.internal_redirect",  # internal redirect
            "api.i18n_js_translations",  # i18n js translations
            "webassets.index",  # webassets files eg. js, css files urls
            "api.action",  # api calls
            "_debug_toolbar.static",  # debug toolbar static files
            "resource.download",  # resource download url
            "dataset_resource.download",  # dataset resource download url
            "util.redirect",  # Pylons redirect
            "package.resource_download",  # Pylons resource download url
            "error.document",
        ]

        # allow 'dcat' endpoints
        if "dcat" in config.get("ckan.plugins", ""):
            allowed_blueprint.extend(
                [
                    "dcat.read_dataset",
                    "dcat.read_catalog",
                    "dcat.rdf_dataset",
                    "dcat.rdf_catalog",
                    "dcat_json_interface.dcat_json",
                    # pylons url
                    "dcat_dataset.read_catalog"
                    "dcat_dataset.read_dataset"
                    "ckanext.dcat.controllers:DCATController.dcat_json",
                ]
            )

        # allow 'datastore' endpoints
        if "datastore" in config.get("ckan.plugins", ""):
            allowed_blueprint.extend(
                [
                    "datastore.dump",
                    # pylons url
                    "ckanext.datastore.controller:DatastoreController.dump",
                ]
            )

        # allow 's3filestore' endpoints
        if "s3filestore" in config.get("ckan.plugins", ""):
            allowed_blueprint.extend(
                [
                    "s3_resource.resource_download",
                    "s3_uploads.uploaded_file_redirect",
                    # pylons url
                    "resource_download.resource_download",
                    "uploaded_file.uploaded_file_redirect",
                ]
            )

        # allow 'googleanalytics' endpoints
        if "googleanalytics" in config.get("ckan.plugins", ""):
            allowed_blueprint.extend(
                [
                    "google_analytics.action",
                    # Pylons url
                    "ckanext.googleanalytics.controller:GAApiController.action",
                ]
            )

        # allow 'security' endpoints
        if "security" in config.get("ckan.plugins", ""):
            allowed_blueprint.extend(
                [
                    "mfa_user.login",
                    "mfa_user.configure_mfa",
                    "mfa_user.new",
                    # Pylons url
                    "ckanext.security.controllers:SecureUserController.request_reset",
                    "ckanext.security.controllers:SecureUserController.perform_reset",
                    "ckanext.security.controllers:MFAUserController.login",
                    "ckanext.security.controllers:MFAUserController.configure_mfa",
                    "ckanext.security.controllers:MFAUserController.new",
                ]
            )

        # allowed blueprint specified the environment variable
        allowed_blueprints_in_env = config.get(
            "ckanext.noanonaccess.allowed_blueprint", []
        )
        if allowed_blueprints_in_env:
            allowed_blueprint.extend(allowed_blueprints_in_env.split(" "))

        # allow if current blueprint is in allowed blueprint route
        restricted_access = not (current_blueprint in allowed_blueprint)

        # allowed regex path list specified in the environment variable
        allowed_paths = config.get("ckanext.noanonaccess.allowed_paths", [])
        if allowed_paths:
            allowed_paths = allowed_paths.split(" ")

        for path in allowed_paths:
            if re.match(path, current_path):
                restricted_access = False
                break

        # set redirect path specified in the environment variable
        redirect_path_config = config.get("ckanext.noanonaccess.redirect_path", [])
        if not redirect_path_config:
            redirect_path = "user.login"  # route name
        else:
            site_url = config.get("ckan.site_url")
            redirect_path = site_url + redirect_path_config  # absolute URL

        # restrict access for anonymous user
        if is_anonoumous_user and restricted_access:
            return self._redirect_with_optional_came_from(redirect_path)

    # ------------------- helpers -------------------

    def _redirect_with_optional_came_from(self, redirect_path: str):
        """
        Build the redirect response. If configured, append a 'came_from' (or custom name)
        parameter with the original URL (or path), with loop protection.
        """
        # Config flags (defaults preserve original behavior)
        append = tk.asbool(config.get('ckanext.noanonaccess.append_came_from', False))
        param = config.get('ckanext.noanonaccess.came_from_param', 'came_from')
        full = tk.asbool(config.get('ckanext.noanonaccess.came_from_full_url', True))

        # disallow list: space or comma separated
        raw_disallow = config.get('ckanext.noanonaccess.came_from_disallow_paths', '')
        if raw_disallow.strip():
            disallow = tuple(raw_disallow.replace(',', ' ').split())
        else:
            disallow = _DEFAULT_DISALLOW_PATHS

        original_url = tk.request.url if full else (tk.request.path or '/')
        if any((tk.request.path or '').startswith(bp) for bp in disallow):
            original_url = (config.get('ckan.site_url') or '/')

        if not append:
            # legacy behavior: do not add came_from
            return self._plain_redirect(redirect_path)

        # append came_from
        if redirect_path.startswith(('http://', 'https://', '/')):
            u = urlparse(redirect_path)
            q = dict(parse_qsl(u.query))
            q[param] = original_url
            new = u._replace(query=urlencode(q, doseq=True))
            location = urlunparse(new)
            return tk.redirect_to(location)
        else:
            # route name
            return tk.redirect_to(tk.url_for(redirect_path, **{param: original_url}))

    @staticmethod
    def _plain_redirect(redirect_path: str):
        """Redirect without any came_from parameter."""
        if redirect_path.startswith(('http://', 'https://', '/')):
            return tk.redirect_to(redirect_path)
        else:
            return tk.redirect_to(tk.url_for(redirect_path))
