# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.
import base64
import functools
import json
import logging
import os

import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest

from odoo import api, http, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo import registry as registry_get

from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home
from odoo.addons.web.controllers.main import db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect


_logger = logging.getLogger(__name__)


#----------------------------------------------------------
# helpers
#----------------------------------------------------------
def fragment_to_query_string(func):
    print("\n-=-=-= (auth_oauth main) -=-=(line 29)===--------- def fragment_to_query_string ")
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        print("\n-=-=-= (auth_oauth main) -=-====(line 32)--------- def wrapper    a: ",a,"-=-=-=-=-kw:",kw)
        kw.pop('debug', False)
        if not kw:
            return """<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>"""
        return func(self, *a, **kw)
    return wrapper


#----------------------------------------------------------
# Controller
#----------------------------------------------------------
class OAuthLogin(Home):
    def list_providers(self):
        print("\n-=-=-=-=-== (auth_oauth main) ==--------- def list_providers ")
        try:
            providers = request.env['auth.oauth.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            providers = []
        for provider in providers:
            return_url = request.httprequest.url_root + 'auth_oauth/signin'
            print("\n\n\n===(line 64)=== (auth_oauth main) ==def list_providers===========",request.httprequest.url_root ,"---------", return_url)
            state = self.get_state(provider)
            print("\n\n===(line 66)=== (auth_oauth main) ==def list_providers===========",state)
            params = dict(
                response_type='token',
                client_id=provider['client_id'],
                redirect_uri=return_url,
                scope=provider['scope'],
                state=json.dumps(state),
                # nonce=base64.urlsafe_b64encode(os.urandom(16)),
            )
            provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.urls.url_encode(params))
        print("\n-=-=-(line 75 )=-=- (auth_oauth main) ====--- def list_providers ::: providers:  ",provider['auth_link'])
        return providers

    def get_state(self, provider):
        print("\n-=-( Function Call ) =-=-(line 80)=-==== (auth_oauth main) --------- def get_state:::werkzeug.urls.url_encode ")
        redirect = request.params.get('redirect') or 'web'
        if not redirect.startswith(('//', 'http://', 'https://')):
            redirect = '%s%s' % (request.httprequest.url_root, redirect[1:] if redirect[0] == '/' else redirect)
        state = dict(
            d=request.session.db,
            p=provider['id'],
            r=werkzeug.urls.url_quote_plus(redirect),
        )
        token = request.params.get('token')
        if token:
            state['t'] = token
        print("\n-=-=-=-(line 92)=-==== (auth_oauth main) --------- def get_state ::: state: ",state)
        return state

    @http.route()
    def web_login(self, *args, **kw):
        print("\n-=-=-( Function Call ) =--(line 97)==-(auth_oauth main)--------- web_login",args,"-=-=-=-=-=-=kw",kw)
        ensure_db()
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            # Redirect if already logged in and redirect param is present
            print("\n\n----(line 101)--- (auth_oauth main) --------- def web_login ------Redirect if already logged---------")
            return request.redirect(request.params.get('redirect'))
        providers = self.list_providers()


        response = super(OAuthLogin, self).web_login(*args, **kw)
        print("\n\n---( line 107 )--- (auth_oauth main) ---------- def web_login ::: response: ---",response)
        if response.is_qweb:
            error = request.params.get('oauth_error')
            if error == '1':
                error = _("Sign up is not allowed on this database.")
            elif error == '2':
                error = _("Access Denied")
            elif error == '3':
                error = _("You do not have access to this database or your invitation has expired. Please ask for an invitation and be sure to follow the link in your invitation email.")
            else:
                error = None

            response.qcontext['providers'] = providers
            if error:
                response.qcontext['error'] = error
        print("\n-=-=(line 122 )-=-=-= (auth_oauth main) ===--------- def web_login ::: response: ", response)
        return response

    def get_auth_signup_qcontext(self):
        print("\n-=-=-( Function Call ) =--(line 126)==- (auth_oauth main) ====----- get_auth_signup_qcontext")
        result = super(OAuthLogin, self).get_auth_signup_qcontext()
        result["providers"] = self.list_providers()
        return result


class OAuthController(http.Controller):

    @http.route('/auth_oauth/signin', type='http', auth='none')
    @fragment_to_query_string
    def signin(self, **kw):
        print("\n-=-=-= ( Function Call ) -=-=(line 137)=== (auth_oauth main) ===--------------- def s i g n i n ",kw)
        state = json.loads(kw['state'])
        print("\n      ---(auth_oauth main)---(line 139)-------::: state :::", state)
        dbname = state['d']
        if not http.db_filter([dbname]):
            return BadRequest()
        provider = state['p']
        print("\n--(auth_oauth main)--(line 144)---  ---provider-----------  ", provider)
        context = state.get('c', {})
        registry = registry_get(dbname)
        with registry.cursor() as cr:
            print("\n   r (auth_oauth main)  ------(line 148)------- r  registry.cursor()",registry.cursor())
            try:
                env = api.Environment(cr, SUPERUSER_ID, context)
                credentials = env['res.users'].sudo().auth_oauth(provider, kw)
                print("\n----(line 152)------credentials-----------  ", credentials)
                cr.commit()
                action = state.get('a')
                menu = state.get('m')
                redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False
                print("\n----(line 157)------redirect-----------  ", redirect)
                url = '/web'
                if redirect:

                    print("\n-- (auth_oauth main) ---(line 161)-----if redirect-----------  ")
                    url = redirect





                elif action:
                    print("\n--- (auth_oauth main) --(line 162)-----elif action-----------  ")
                    url = '/web#action=%s' % action
                elif menu:
                    print("\n-- (auth_oauth main) ---(line 165)-----elif menu-----------  ")
                    url = '/web#menu_id=%s' % menu
                
                


                print("\n-- (auth_oauth main) --- (line 178)  :::  resp :  ")
                resp = login_and_redirect(*credentials, redirect_url=url)
                # Since /web is hardcoded, verify user has right to land on it
                if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user.has_group('base.group_user'):
                    resp.location = '/'
                    print("\n-- (auth_oauth main) --(line 183)------if werkzeug.urls-----------  ")
                print("\n-- (auth_oauth main) --(line 184)------  return resp  --------  ",resp)
                return resp
           


            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/web/login?oauth_error=1"
                print("\n---- (auth_oauth main) --(line 186)------url-----------  ",url)
            except AccessDenied:
                # oauth credentials not valid, user could be on a temporary session
                _logger.info('OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                url = "/web/login?oauth_error=3"
                redirect = request.redirect(url, 303)
                redirect.autocorrect_location_header = False
                print("\n---- (auth_oauth main) --(line 193)------return redirect-----------  ")
                return redirect
            except Exception as e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/web/login?oauth_error=2"
        print("\n--- (auth_oauth main) ---(line 199)----return set_cookie_and_redirect(url)-----------  ")
        return set_cookie_and_redirect(url)

    @http.route('/auth_oauth/oea', type='http', auth='none')
    def oea(self, **kw):
        print("\n==(line 202)== (auth_oauth main) ======  def oea   ======= login user via Odoo Account provider")
        """login user via Odoo Account provider"""
        dbname = kw.pop('db', None)
        if not dbname:
            print("===(line 206)==== (auth_oauth main) ========(1)no db")
            dbname = db_monodb()
        if not dbname:
            print("===(line 209)=== (auth_oauth main) =========(2)if not dbname")
            return BadRequest()
        if not http.db_filter([dbname]):
            print("===(line 212)==== (auth_oauth main) ========if not http.db_filter([dbname]):")
            return BadRequest()

        registry = registry_get(dbname)
        with registry.cursor() as cr:
            try:
                env = api.Environment(cr, SUPERUSER_ID, {})
                provider = env.ref('auth_oauth.provider_openerp')
            except ValueError:
                return set_cookie_and_redirect('/web?db=%s' % dbname)
            assert provider._name == 'auth.oauth.provider'

        state = {
            'd': dbname,
            'p': provider.id,
            'c': {'no_user_creation': True},
        }

        kw['state'] = json.dumps(state)
        print("-=-(line 231)=-=- (auth_oauth main) =-=-=-=  def oea  -=-=-=- kw[state]",kw['state'])
        return self.signin(**kw)
