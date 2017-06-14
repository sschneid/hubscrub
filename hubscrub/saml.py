import json
from hashlib import md5
from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from flask import make_response, redirect, request, session

from hubscrub import app
from hubscrub.redis import init_redis_client

import hubscrub.config as config


app.config['SECRET_KEY'] = md5(config.saml_config.encode('utf-8')).hexdigest()

def init_saml_auth(flask_request):
    auth = OneLogin_Saml2_Auth(flask_request, json.loads(config.saml_config))

    return auth


def prepare_flask_request(request):
    url_data = urlparse(request.url)

    return {
        'https': 'on',
        'http_host': request.host,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }


def get_saml_auth(request):
    if config.saml_config is not None:
        flask_request = prepare_flask_request(request)

        return init_saml_auth(flask_request)
    else:
        return None


@app.route('/metadata', methods=['GET'])
def metadata():
    auth = get_saml_auth(request)

    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if not errors:
        response = make_response(metadata, 200)
        response.headers['Content-Type'] = 'text/xml'
    else:
        response = make_response(', '.join(errors), 500)

    return response


@app.route('/saml/login', methods=['GET'])
def saml_login():
    auth = get_saml_auth(request)

    if 'return_to' in request.args:
        return redirect(auth.login(request.args.get('return_to')))
    else:
        return redirect(auth.login())


@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    auth = get_saml_auth(request)

    auth.process_response()
    errors = auth.get_errors()

    if not errors:
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlSessionIndex'] = auth.get_session_index()

        if ('RelayState' in request.form) and ('/saml/login' not in request.form['RelayState']):
            return redirect(auth.redirect_to(request.form['RelayState']))
        else:
            return redirect(auth.redirect_to('/'))
    else:
        return render_template('login.html')
