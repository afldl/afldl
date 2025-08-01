# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
`.AuthHandler`
"""

import weakref, os
from paramiko.common import cMSG_SERVICE_REQUEST, cMSG_DISCONNECT, \
    DISCONNECT_SERVICE_NOT_AVAILABLE, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, \
    cMSG_USERAUTH_REQUEST, cMSG_SERVICE_ACCEPT, DEBUG, AUTH_SUCCESSFUL, INFO, \
    cMSG_USERAUTH_SUCCESS, cMSG_USERAUTH_FAILURE, AUTH_PARTIALLY_SUCCESSFUL, \
    cMSG_USERAUTH_INFO_REQUEST, WARNING, AUTH_FAILED, cMSG_USERAUTH_PK_OK, \
    cMSG_USERAUTH_INFO_RESPONSE, MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT, \
    MSG_USERAUTH_REQUEST, MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE, \
    MSG_USERAUTH_BANNER, MSG_USERAUTH_INFO_REQUEST, MSG_USERAUTH_INFO_RESPONSE, \
    cMSG_USERAUTH_GSSAPI_RESPONSE, cMSG_USERAUTH_GSSAPI_TOKEN, \
    cMSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, cMSG_USERAUTH_GSSAPI_ERROR, \
    cMSG_USERAUTH_GSSAPI_ERRTOK, cMSG_USERAUTH_GSSAPI_MIC,\
    MSG_USERAUTH_GSSAPI_RESPONSE, MSG_USERAUTH_GSSAPI_TOKEN, \
    MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, MSG_USERAUTH_GSSAPI_ERROR, \
    MSG_USERAUTH_GSSAPI_ERRTOK, MSG_USERAUTH_GSSAPI_MIC

from paramiko.message import Message
from paramiko.py3compat import bytestring
from paramiko.ssh_exception import SSHException, AuthenticationException, \
    BadAuthenticationType, PartialAuthentication
from paramiko.server import InteractiveQuery
from paramiko.ssh_gss import GSSAuth


class AuthHandler (object):
    """
    Internal class to handle the mechanics of authentication.
    """

    def __init__(self, transport):
        self.transport = weakref.proxy(transport)
        self.username = None
        self.authenticated = False
        self.auth_event = None
        self.auth_method = ''
        self.banner = None
        self.password = None
        self.private_key = None
        self.interactive_handler = None
        self.submethods = None
        # for server mode:
        self.auth_username = None
        self.auth_fail_count = 0
        # for GSSAPI
        self.gss_host = None
        self.gss_deleg_creds = True

    def is_authenticated(self):
        return self.authenticated

    def get_username(self):
        if self.transport.server_mode:
            return self.auth_username
        else:
            return self.username

    def auth_none(self, username, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = 'none'
            self.username = username
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_publickey(self, username, key, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = 'publickey'
            self.username = username
            self.private_key = key
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_password(self, username, password, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = 'password'
            self.username = username
            self.password = password
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_interactive(self, username, handler, event, submethods=''):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = 'keyboard-interactive'
            self.username = username
            self.interactive_handler = handler
            self.submethods = submethods
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_gssapi_with_mic(self, username, gss_host, gss_deleg_creds, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = 'gssapi-with-mic'
            self.username = username
            self.gss_host = gss_host
            self.gss_deleg_creds = gss_deleg_creds
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_gssapi_keyex(self, username, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = 'gssapi-keyex'
            self.username = username
            self._request_auth()
        finally:
            self.transport.lock.release()

    def abort(self):
        if self.auth_event is not None:
            self.auth_event.set()

    ###  internals...

    def _request_auth(self, keyword=None):
        m = Message()
        if keyword == 'cMSG_SERVICE_REQUEST':
            print cMSG_SERVICE_REQUEST
            fuzz_value = os.urandom(len(cMSG_SERVICE_REQUEST))
            print 'fuzz_value'
            print fuzz_value
            m.add_byte(fuzz_value)
        else:
            m.add_byte(cMSG_SERVICE_REQUEST)
        if keyword == 'ssh-userauth':
            print 'ssh-userauth'
            fuzz_value = os.urandom(len('ssh-userauth'))
            print 'fuzz_value'
            print [i for i in list(fuzz_value)]
            m.add_string(fuzz_value)
        else:
            m.add_string('ssh-userauth')
        self.transport._send_message(m)

    def _disconnect_service_not_available(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_SERVICE_NOT_AVAILABLE)
        m.add_string('Service not available')
        m.add_string('en')
        self.transport._send_message(m)
        self.transport.close()

    def _disconnect_no_more_auth(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
        m.add_string('No more auth methods available')
        m.add_string('en')
        self.transport._send_message(m)
        self.transport.close()

    def _get_session_blob(self, key, service, username):
        m = Message()

        # A default is set here
        if self.transport.session_id:
            sesid = self.transport.session_id
        else:
            sesid = 'SESID'

        m.add_string(sesid)
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string(service)
        m.add_string('publickey')
        m.add_boolean(True)
        m.add_string(key.get_name())
        m.add_string(key)
        return m.asbytes()

    def wait_for_response(self, event):
        while True:
            event.wait(0.1)
            if not self.transport.is_active():
                e = self.transport.get_exception()
                if (e is None) or issubclass(e.__class__, EOFError):
                    e = AuthenticationException('Authentication failed.')
                raise e
            if event.is_set():
                break
        if not self.is_authenticated():
            e = self.transport.get_exception()
            if e is None:
                e = AuthenticationException('Authentication failed.')
            # this is horrible.  Python Exception isn't yet descended from
            # object, so type(e) won't work. :(
            if issubclass(e.__class__, PartialAuthentication):
                return e.allowed_types
            raise e
        return []

    def _parse_service_request(self, m):
        service = m.get_text()
        if self.transport.server_mode and (service == 'ssh-userauth'):
            # accepted
            m = Message()
            m.add_byte(cMSG_SERVICE_ACCEPT)
            m.add_string(service)
            self.transport._send_message(m)
            return
        # dunno this one
        self._disconnect_service_not_available()

    def custom_parse_service_request(self, keyword=None):
        self.transport._log(DEBUG, 'userauth is OK')
        m = Message()
        if keyword == 'cMSG_USERAUTH_REQUEST':
            print cMSG_USERAUTH_REQUEST
            fuzz_value = os.urandom(len(cMSG_USERAUTH_REQUEST))
            print 'fuzz_value'
            print fuzz_value
            m.add_byte(fuzz_value)
        else:
            m.add_byte(cMSG_USERAUTH_REQUEST)
        if keyword == 'username':
            print self.username
            fuzz_value = os.urandom(len(self.username))
            print 'fuzz_value'
            print [i for i in list(fuzz_value)]
            m.add_string(fuzz_value)
        else:
            m.add_string(self.username)
        if keyword == 'ssh-connection':
            print 'ssh-connection'
            fuzz_value = os.urandom(len('ssh-connection'))
            print 'fuzz_value'
            print [i for i in list(fuzz_value)]
            m.add_string(fuzz_value)
        else:
            m.add_string('ssh-connection')
        if keyword == 'auth_method':
            print self.auth_method
            fuzz_value = os.urandom(len(self.auth_method))
            print 'fuzz_value'
            print [i for i in list(fuzz_value)]
            m.add_string(fuzz_value)
        else:
            m.add_string(self.auth_method)
        if self.auth_method == 'password':
            m.add_boolean(False)
            password = bytestring(self.password)
            if keyword == 'password':
                print password
                fuzz_value = os.urandom(len(password))
                print 'fuzz_value'
                print[i for i in list(fuzz_value)]
                m.add_string(fuzz_value)
            else:
                m.add_string(password)
        elif self.auth_method == 'publickey':
            m.add_boolean(True)
            m.add_string(self.private_key.get_name())
            m.add_string(self.private_key)
            blob = self._get_session_blob(self.private_key, 'ssh-connection', self.username)
            sig = self.private_key.sign_ssh_data(blob)
            m.add_string(sig)
        elif self.auth_method == 'keyboard-interactive':
            m.add_string('')
            m.add_string(self.submethods)
        elif self.auth_method == "gssapi-with-mic":
            sshgss = GSSAuth(self.auth_method, self.gss_deleg_creds)
            m.add_bytes(sshgss.ssh_gss_oids())
            # send the supported GSSAPI OIDs to the server
            self.transport._send_message(m)
            ptype, m = self.transport.packetizer.read_message()
            if ptype == MSG_USERAUTH_BANNER:
                self._parse_userauth_banner(m)
                ptype, m = self.transport.packetizer.read_message()
            if ptype == MSG_USERAUTH_GSSAPI_RESPONSE:
                # Read the mechanism selected by the server. We send just
                # the Kerberos V5 OID, so the server can only respond with
                # this OID.
                mech = m.get_string()
                m = Message()
                m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                m.add_string(sshgss.ssh_init_sec_context(self.gss_host,
                                                         mech,
                                                         self.username,))
                self.transport._send_message(m)
                while True:
                    ptype, m = self.transport.packetizer.read_message()
                    if ptype == MSG_USERAUTH_GSSAPI_TOKEN:
                        srv_token = m.get_string()
                        next_token = sshgss.ssh_init_sec_context(self.gss_host,
                                                                 mech,
                                                                 self.username,
                                                                 srv_token)
                        # After this step the GSSAPI should not return any
                        # token. If it does, we keep sending the token to
                        # the server until no more token is returned.
                        if next_token is None:
                            break
                        else:
                            m = Message()
                            m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                            m.add_string(next_token)
                            self.transport.send_message(m)
                else:
                    raise SSHException("Received Package: %s" % MSG_NAMES[ptype])
                m = Message()
                m.add_byte(cMSG_USERAUTH_GSSAPI_MIC)
                # send the MIC to the server
                m.add_string(sshgss.ssh_get_mic(self.transport.session_id))
            elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
                # RFC 4462 says we are not required to implement GSS-API
                # error messages.
                # See RFC 4462 Section 3.8 in
                # http://www.ietf.org/rfc/rfc4462.txt
                raise SSHException("Server returned an error token")
            elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
                maj_status = m.get_int()
                min_status = m.get_int()
                err_msg = m.get_string()
                lang_tag = m.get_string()  # we don't care!
                raise SSHException("GSS-API Error:\nMajor Status: %s\n\
                                    Minor Status: %s\ \nError Message:\
                                     %s\n") % (str(maj_status),
                                               str(min_status),
                                               err_msg)
            elif ptype == MSG_USERAUTH_FAILURE:
                self._parse_userauth_failure(m)
                return
            else:
                raise SSHException("Received Package: %s" % MSG_NAMES[ptype])
        elif self.auth_method == 'gssapi-keyex' and\
            self.transport.gss_kex_used:
            kexgss = self.transport.kexgss_ctxt
            kexgss.set_username(self.username)
            mic_token = kexgss.ssh_get_mic(self.transport.session_id)
            m.add_string(mic_token)
        elif self.auth_method == 'none':
            pass
        else:
            # raise SSHException('Unknown auth method "%s"' % self.auth_method)
            self.transport._send_message(m)

        self.transport._send_message(m)

    def _parse_service_accept(self, m):
        service = m.get_text()
        if service == 'ssh-userauth':
            self.transport._log(DEBUG, 'userauth is OK')
            m = Message()
            m.add_byte(cMSG_USERAUTH_REQUEST)
            m.add_string(self.username)
            m.add_string('ssh-connection')
            m.add_string(self.auth_method)
            if self.auth_method == 'password':
                m.add_boolean(False)
                password = bytestring(self.password)
                m.add_string(password)
            elif self.auth_method == 'publickey':
                m.add_boolean(True)
                m.add_string(self.private_key.get_name())
                m.add_string(self.private_key)
                blob = self._get_session_blob(self.private_key, 'ssh-connection', self.username)
                sig = self.private_key.sign_ssh_data(blob)
                m.add_string(sig)
            elif self.auth_method == 'keyboard-interactive':
                m.add_string('')
                m.add_string(self.submethods)
            elif self.auth_method == "gssapi-with-mic":
                sshgss = GSSAuth(self.auth_method, self.gss_deleg_creds)
                m.add_bytes(sshgss.ssh_gss_oids())
                # send the supported GSSAPI OIDs to the server
                self.transport._send_message(m)
                ptype, m = self.transport.packetizer.read_message()
                if ptype == MSG_USERAUTH_BANNER:
                    self._parse_userauth_banner(m)
                    ptype, m = self.transport.packetizer.read_message()
                if ptype == MSG_USERAUTH_GSSAPI_RESPONSE:
                    # Read the mechanism selected by the server. We send just
                    # the Kerberos V5 OID, so the server can only respond with
                    # this OID.
                    mech = m.get_string()
                    m = Message()
                    m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                    m.add_string(sshgss.ssh_init_sec_context(self.gss_host,
                                                             mech,
                                                             self.username,))
                    self.transport._send_message(m)
                    while True:
                        ptype, m = self.transport.packetizer.read_message()
                        if ptype == MSG_USERAUTH_GSSAPI_TOKEN:
                            srv_token = m.get_string()
                            next_token = sshgss.ssh_init_sec_context(self.gss_host,
                                                                     mech,
                                                                     self.username,
                                                                     srv_token)
                            # After this step the GSSAPI should not return any
                            # token. If it does, we keep sending the token to
                            # the server until no more token is returned.
                            if next_token is None:
                                break
                            else:
                                m = Message()
                                m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                                m.add_string(next_token)
                                self.transport.send_message(m)
                    else:
                        raise SSHException("Received Package: %s" % MSG_NAMES[ptype])
                    m = Message()
                    m.add_byte(cMSG_USERAUTH_GSSAPI_MIC)
                    # send the MIC to the server
                    m.add_string(sshgss.ssh_get_mic(self.transport.session_id))
                elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
                    # RFC 4462 says we are not required to implement GSS-API
                    # error messages.
                    # See RFC 4462 Section 3.8 in
                    # http://www.ietf.org/rfc/rfc4462.txt
                    raise SSHException("Server returned an error token")
                elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
                    maj_status = m.get_int()
                    min_status = m.get_int()
                    err_msg = m.get_string()
                    lang_tag = m.get_string()  # we don't care!
                    raise SSHException("GSS-API Error:\nMajor Status: %s\n\
                                        Minor Status: %s\ \nError Message:\
                                         %s\n") % (str(maj_status),
                                                   str(min_status),
                                                   err_msg)
                elif ptype == MSG_USERAUTH_FAILURE:
                    self._parse_userauth_failure(m)
                    return
                else:
                    raise SSHException("Received Package: %s" % MSG_NAMES[ptype])
            elif self.auth_method == 'gssapi-keyex' and\
                self.transport.gss_kex_used:
                kexgss = self.transport.kexgss_ctxt
                kexgss.set_username(self.username)
                mic_token = kexgss.ssh_get_mic(self.transport.session_id)
                m.add_string(mic_token)
            elif self.auth_method == 'none':
                pass
            else:
                raise SSHException('Unknown auth method "%s"' % self.auth_method)
            self.transport._send_message(m)
        else:
            self.transport._log(DEBUG, 'Service request "%s" accepted (?)' % service)

    def _send_auth_result(self, username, method, result):
        # okay, send result
        m = Message()
        if result == AUTH_SUCCESSFUL:
            self.transport._log(INFO, 'Auth granted (%s).' % method)
            m.add_byte(cMSG_USERAUTH_SUCCESS)
            self.authenticated = True
        else:
            self.transport._log(INFO, 'Auth rejected (%s).' % method)
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string(self.transport.server_object.get_allowed_auths(username))
            if result == AUTH_PARTIALLY_SUCCESSFUL:
                m.add_boolean(True)
            else:
                m.add_boolean(False)
                self.auth_fail_count += 1
        self.transport._send_message(m)
        if self.auth_fail_count >= 10:
            self._disconnect_no_more_auth()
        if result == AUTH_SUCCESSFUL:
            self.transport._auth_trigger()

    def _interactive_query(self, q):
        # make interactive query instead of response
        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_REQUEST)
        m.add_string(q.name)
        m.add_string(q.instructions)
        m.add_string(bytes())
        m.add_int(len(q.prompts))
        for p in q.prompts:
            m.add_string(p[0])
            m.add_boolean(p[1])
        self.transport._send_message(m)
 
    def _parse_userauth_request(self, m):
        if not self.transport.server_mode:
            # er, uh... what?
            m = Message()
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string('none')
            m.add_boolean(False)
            self.transport._send_message(m)
            return
        if self.authenticated:
            # ignore
            return
        username = m.get_text()
        service = m.get_text()
        method = m.get_text()
        self.transport._log(DEBUG, 'Auth request (type=%s) service=%s, username=%s' % (method, service, username))
        if service != 'ssh-connection':
            self._disconnect_service_not_available()
            return
        if (self.auth_username is not None) and (self.auth_username != username):
            self.transport._log(WARNING, 'Auth rejected because the client attempted to change username in mid-flight')
            self._disconnect_no_more_auth()
            return
        self.auth_username = username
        # check if GSS-API authentication is enabled
        gss_auth = self.transport.server_object.enable_auth_gssapi()

        if method == 'none':
            result = self.transport.server_object.check_auth_none(username)
        elif method == 'password':
            changereq = m.get_boolean()
            password = m.get_binary()
            try:
                password = password.decode('UTF-8')
            except UnicodeError:
                # some clients/servers expect non-utf-8 passwords!
                # in this case, just return the raw byte string.
                pass
            if changereq:
                # always treated as failure, since we don't support changing passwords, but collect
                # the list of valid auth types from the callback anyway
                self.transport._log(DEBUG, 'Auth request to change passwords (rejected)')
                newpassword = m.get_binary()
                try:
                    newpassword = newpassword.decode('UTF-8', 'replace')
                except UnicodeError:
                    pass
                result = AUTH_FAILED
            else:
                result = self.transport.server_object.check_auth_password(username, password)
        elif method == 'publickey':
            sig_attached = m.get_boolean()
            keytype = m.get_text()
            keyblob = m.get_binary()
            try:
                key = self.transport._key_info[keytype](Message(keyblob))
            except SSHException as e:
                self.transport._log(INFO, 'Auth rejected: public key: %s' % str(e))
                key = None
            except:
                self.transport._log(INFO, 'Auth rejected: unsupported or mangled public key')
                key = None
            if key is None:
                self._disconnect_no_more_auth()
                return
            # first check if this key is okay... if not, we can skip the verify
            result = self.transport.server_object.check_auth_publickey(username, key)
            if result != AUTH_FAILED:
                # key is okay, verify it
                if not sig_attached:
                    # client wants to know if this key is acceptable, before it
                    # signs anything...  send special "ok" message
                    m = Message()
                    m.add_byte(cMSG_USERAUTH_PK_OK)
                    m.add_string(keytype)
                    m.add_string(keyblob)
                    self.transport._send_message(m)
                    return
                sig = Message(m.get_binary())
                blob = self._get_session_blob(key, service, username)
                if not key.verify_ssh_sig(blob, sig):
                    self.transport._log(INFO, 'Auth rejected: invalid signature')
                    result = AUTH_FAILED
        elif method == 'keyboard-interactive':
            lang = m.get_string()
            submethods = m.get_string()
            result = self.transport.server_object.check_auth_interactive(username, submethods)
            if isinstance(result, InteractiveQuery):
                # make interactive query instead of response
                self._interactive_query(result)
                return
        elif method == "gssapi-with-mic" and gss_auth:
            sshgss = GSSAuth(method)
            # Read the number of OID mechanisms supported by the client.
            # OpenSSH sends just one OID. It's the Kerveros V5 OID and that's
            # the only OID we support.
            mechs = m.get_int()
            # We can't accept more than one OID, so if the SSH client sends
            # more than one, disconnect.
            if mechs > 1:
                self.transport._log(INFO,
                                    'Disconnect: Received more than one GSS-API OID mechanism')
                self._disconnect_no_more_auth()
            desired_mech = m.get_string()
            mech_ok = sshgss.ssh_check_mech(desired_mech)
            # if we don't support the mechanism, disconnect.
            if not mech_ok:
                self.transport._log(INFO,
                                    'Disconnect: Received an invalid GSS-API OID mechanism')
                self._disconnect_no_more_auth()
            # send the Kerberos V5 GSSAPI OID to the client
            supported_mech = sshgss.ssh_gss_oids("server")
            # RFC 4462 says we are not required to implement GSS-API error
            # messages. See section 3.8 in http://www.ietf.org/rfc/rfc4462.txt
            while True:
                m = Message()
                m.add_byte(cMSG_USERAUTH_GSSAPI_RESPONSE)
                m.add_bytes(supported_mech)
                self.transport._send_message(m)
                ptype, m = self.transport.packetizer.read_message()
                if ptype == MSG_USERAUTH_GSSAPI_TOKEN:
                    client_token = m.get_string()
                    # use the client token as input to establish a secure
                    # context.
                    try:
                        token = sshgss.ssh_accept_sec_context(self.gss_host,
                                                              client_token,
                                                              username)
                    except Exception:
                        result = AUTH_FAILED
                        self._send_auth_result(username, method, result)
                        raise
                    if token is not None:
                        m = Message()
                        m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                        m.add_string(token)
                        self.transport._send_message(m)
                else:
                    raise SSHException("Client asked to handle paket %s"
                                       %MSG_NAMES[ptype])
                # check MIC
                ptype, m = self.transport.packetizer.read_message()
                if ptype == MSG_USERAUTH_GSSAPI_MIC:
                    break
            mic_token = m.get_string()
            try:
                sshgss.ssh_check_mic(mic_token,
                                     self.transport.session_id,
                                     username)
            except Exception:
                result = AUTH_FAILED
                self._send_auth_result(username, method, result)
                raise
            if retval == 0:
                # TODO: Implement client credential saving.
                # The OpenSSH server is able to create a TGT with the delegated
                # client credentials, but this is not supported by GSS-API.
                result = AUTH_SUCCESSFUL
                self.transport.server_object.check_auth_gssapi_with_mic(
                    username, result)
            else:
                result = AUTH_FAILED
        elif method == "gssapi-keyex" and gss_auth:
            mic_token = m.get_string()
            sshgss = self.transport.kexgss_ctxt
            if sshgss is None:
                # If there is no valid context, we reject the authentication
                result = AUTH_FAILED
                self._send_auth_result(username, method, result)
            try:
                sshgss.ssh_check_mic(mic_token,
                                     self.transport.session_id,
                                     self.auth_username)
            except Exception:
                result = AUTH_FAILED
                self._send_auth_result(username, method, result)
                raise
            if retval == 0:
                result = AUTH_SUCCESSFUL
                self.transport.server_object.check_auth_gssapi_keyex(username,
                                                                      result)
            else:
                result = AUTH_FAILED
        else:
            result = self.transport.server_object.check_auth_none(username)
        # okay, send result
        self._send_auth_result(username, method, result)

    def _parse_userauth_success(self, m):
        self.transport._log(INFO, 'Authentication (%s) successful!' % self.auth_method)
        self.authenticated = True
        self.transport._auth_trigger()
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_failure(self, m):
        authlist = m.get_list()
        partial = m.get_boolean()
        if partial:
            self.transport._log(INFO, 'Authentication continues...')
            self.transport._log(DEBUG, 'Methods: ' + str(authlist))
            self.transport.saved_exception = PartialAuthentication(authlist)
        elif self.auth_method not in authlist:
            self.transport._log(DEBUG, 'Authentication type (%s) not permitted.' % self.auth_method)
            self.transport._log(DEBUG, 'Allowed methods: ' + str(authlist))
            self.transport.saved_exception = BadAuthenticationType('Bad authentication type', authlist)
        else:
            self.transport._log(INFO, 'Authentication (%s) failed.' % self.auth_method)
        self.authenticated = False
        self.username = None
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_banner(self, m):
        banner = m.get_string()
        self.banner = banner
        lang = m.get_string()
        self.transport._log(INFO, 'Auth banner: %s' % banner)
        # who cares.
    
    def _parse_userauth_info_request(self, m):
        if self.auth_method != 'keyboard-interactive':
            raise SSHException('Illegal info request from server')
        title = m.get_text()
        instructions = m.get_text()
        m.get_binary()  # lang
        prompts = m.get_int()
        prompt_list = []
        for i in range(prompts):
            prompt_list.append((m.get_text(), m.get_boolean()))
        response_list = self.interactive_handler(title, instructions, prompt_list)
        
        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_RESPONSE)
        m.add_int(len(response_list))
        for r in response_list:
            m.add_string(r)
        self.transport._send_message(m)
    
    def _parse_userauth_info_response(self, m):
        if not self.transport.server_mode:
            raise SSHException('Illegal info response from server')
        n = m.get_int()
        responses = []
        for i in range(n):
            responses.append(m.get_text())
        result = self.transport.server_object.check_auth_interactive_response(responses)
        if isinstance(type(result), InteractiveQuery):
            # make interactive query instead of response
            self._interactive_query(result)
            return
        self._send_auth_result(self.auth_username, 'keyboard-interactive', result)

    _handler_table = {
        MSG_SERVICE_REQUEST: _parse_service_request,
        MSG_SERVICE_ACCEPT: _parse_service_accept,
        MSG_USERAUTH_REQUEST: _parse_userauth_request,
        MSG_USERAUTH_SUCCESS: _parse_userauth_success,
        MSG_USERAUTH_FAILURE: _parse_userauth_failure,
        MSG_USERAUTH_BANNER: _parse_userauth_banner,
        MSG_USERAUTH_INFO_REQUEST: _parse_userauth_info_request,
        MSG_USERAUTH_INFO_RESPONSE: _parse_userauth_info_response,
    }
