from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.signals import request_started
from django.http.cookie import SimpleCookie
from django.utils import six, timezone
from django.conf import settings

from easyaudit.models import RequestEvent
from easyaudit.middleware.easyaudit import get_current_request,\
                                           get_current_user

from easyaudit.settings import REMOTE_ADDR_HEADER, UNREGISTERED_URLS,\
                               WATCH_REQUEST_EVENTS, USING_DRF

import re


def should_log_url(url):
    # check if current url is blacklisted
    for unregistered_url in UNREGISTERED_URLS:
        pattern = re.compile(unregistered_url)
        if pattern.match(url):
            return False
    return True


def request_started_handler(sender, environ, **kwargs):
    if not should_log_url(environ['PATH_INFO']):
        return

    user = None

    if not USING_DRF:
        # get the user from cookies
        if environ.get('HTTP_COOKIE'):
            cookie = SimpleCookie() # python3 compatibility
            cookie.load(environ['HTTP_COOKIE'])

            session_cookie_name = settings.SESSION_COOKIE_NAME
            if session_cookie_name in cookie:
                session_id = cookie[session_cookie_name].value

                try:
                    session = Session.objects.get(session_key=session_id)
                except Session.DoesNotExist:
                    session = None

                if session:
                    user_id = session.get_decoded().get('_auth_user_id')
                    try:
                        user = get_user_model().objects.get(id=user_id)
                    except:
                        user = None

        request_event = RequestEvent.objects.create(
            url=environ['PATH_INFO'],
            method=environ['REQUEST_METHOD'],
            query_string=environ['QUERY_STRING'],
            user=user,
            remote_ip=environ[REMOTE_ADDR_HEADER],
            datetime=timezone.now()
        )

    # Use a Middleware to obtain the user from the Request
    else:
        if get_current_request():
            try:
                user = get_current_user()
            except:
                user = None
            else:
                request = get_current_request()

                query_dict = getattr(get_current_request(), 'GET')
                if query_dict:
                    query_string = ','.join(['{}={}'.format(key, value)
                                             for key, value in query_dict.items()])
                else:
                    query_string = ''

                request_event = RequestEvent.objects.create(
                    url=getattr(request, 'path_info'),
                    method=getattr(request, 'method'),
                    query_string=query_string,
                    user=user,
                    remote_ip=getattr(request, 'path_info'),
                    datetime=timezone.now()
                )


if WATCH_REQUEST_EVENTS:
    request_started.connect(request_started_handler, dispatch_uid='easy_audit_signals_request_started')
