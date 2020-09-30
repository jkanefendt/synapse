# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import re
from typing import TYPE_CHECKING, Callable, Dict, Optional, Set, Tuple

import attr
import saml2
import saml2.response
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.cache import TooOld
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.s_utils import status_message_factory, success_status_factory
from saml2.samlp import STATUS_REQUEST_DENIED, STATUS_SUCCESS

from synapse.api.errors import AuthError, SynapseError
from synapse.config import ConfigError
from synapse.config.saml2_config import SamlAttributeRequirement
from synapse.http.servlet import parse_string
from synapse.http.site import SynapseRequest
from synapse.module_api import ModuleApi
from synapse.types import (
    UserID,
    map_username_to_mxid_localpart,
    mxid_localpart_allowed_characters,
)
from synapse.util.async_helpers import Linearizer
from synapse.util.iterutils import chunk_seq

if TYPE_CHECKING:
    import synapse.server

logger = logging.getLogger(__name__)


@attr.s
class Saml2SessionData:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time = attr.ib()
    # The user interactive authentication session ID associated with this SAML
    # session (or None if this SAML session is for an initial login).
    ui_auth_session_id = attr.ib(type=Optional[str], default=None)


class SamlHandler:
    def __init__(self, hs: "synapse.server.HomeServer"):
        self.hs = hs
        self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()
        self._registration_handler = hs.get_registration_handler()

        self._clock = hs.get_clock()
        self._datastore = hs.get_datastore()
        self._hostname = hs.hostname
        self._saml2_session_lifetime = hs.config.saml2_session_lifetime
        self._grandfathered_mxid_source_attribute = (
            hs.config.saml2_grandfathered_mxid_source_attribute
        )
        self._saml2_attribute_requirements = hs.config.saml2.attribute_requirements

        # plugin to do custom mapping from saml response to mxid
        self._user_mapping_provider = hs.config.saml2_user_mapping_provider_class(
            hs.config.saml2_user_mapping_provider_config,
            ModuleApi(hs, hs.get_auth_handler()),
        )

        # identifier for the external_ids table
        self._auth_provider_id = "saml"

        # a map from saml session id to Saml2SessionData object
        self._outstanding_requests_dict = {}  # type: Dict[str, Saml2SessionData]

        # a lock on the mappings
        self._mapping_lock = Linearizer(name="saml_mapping", clock=self._clock)

    def handle_redirect_request(
        self, client_redirect_url: bytes, ui_auth_session_id: Optional[str] = None
    ) -> bytes:
        """Handle an incoming request to /login/sso/redirect

        Args:
            client_redirect_url: the URL that we should redirect the
                client to when everything is done
            ui_auth_session_id: The session ID of the ongoing UI Auth (or
                None if this is a login).

        Returns:
            URL to redirect to
        """
        reqid, info = self._saml_client.prepare_for_authenticate(
            relay_state=client_redirect_url
        )

        # Since SAML sessions timeout it is useful to log when they were created.
        logger.info("Initiating a new SAML session: %s" % (reqid,))

        now = self._clock.time_msec()
        self._outstanding_requests_dict[reqid] = Saml2SessionData(
            creation_time=now, ui_auth_session_id=ui_auth_session_id,
        )

        for key, value in info["headers"]:
            if key == "Location":
                return value

        # this shouldn't happen!
        raise Exception("prepare_for_authenticate didn't return a Location header")

    def _find_session_from_user(self, username):
        """Find the user local session in the SAML local cache.

        A user should be logged into only one IdP/source; therefore only one session
        should exist into the local cache. However in case of a code exception we may
        have multiple sessions stored in the local cache. In that case we select the last
        session and remove other ones.

        Args:
            username (bytes): the mxid localpart

        Returns:
            dict: last SAML session info of the username
        """
        subjects = self._saml_client.users.subjects()
        sessions = []
        # Find all sessions for a specific subject
        for name_id in subjects:
            # We should always have one source only
            for source in self._saml_client.users.sources(name_id):
                try:
                    info = self._saml_client.users.get_info_from(name_id, source)
                except TooOld:
                    continue
                # If the username is found, append the session info
                if (
                    "ava" in info
                    and "uid" in info["ava"]
                    and username in info["ava"]["uid"]
                ):
                    info["entity"] = source
                    sessions.append(info)

        sessions.sort(key=lambda i: i["not_on_or_after"])
        try:
            # Retrieve last session
            last_session = sessions.pop()
            # We should have only one session active for one person
            # This should never match but removing these staled sessions anyway
            [self._saml_client.local_logout(session["name_id"]) for session in sessions]
            return last_session
        except IndexError:
            return None

    def _find_mxid_from_name_id(self, name_id):
        """Find a mxid for a SAML NameID.

        Args:
            name_id (NameID): a SAML Name ID instance

        Returns:
            bytes: a mxid localpart
        """
        try:
            attributes = self._saml_client.users.get_identity(name_id, None, False)
            mxid_attr = self._user_mapping_provider._mxid_source_attribute
            for attribute in attributes:
                if mxid_attr in attribute:
                    return "@%s:%s" % (
                        attribute[mxid_attr][0],
                        self._auth_handler.hs.hostname,
                    )
        except Exception:
            pass
        return None

    async def _logout(self, mxid):
        """Logout a user and all its device from the homeserver

        Args:
            mxid (bytes): the user mxid

        Returns:
            bytes: URL to redirect to
        """
        # first delete all of the user's devices
        await self._device_handler.delete_all_devices_for_user(mxid)

        # .. and then delete any access tokens which weren't associated with
        # devices.
        await self._auth_handler.delete_access_tokens_for_user(mxid)

    def create_logout_request(self, user, access_token):
        """Create a SAML logout request using HTTP redirect binding

        Implements step 1 of the 'Single Logout Profile' specification: this
        method will create the HTTP response to a call to /logout. The response is
        an HTTP redirect to the IdP with a query string parameter called 'SAMLRequest'
        containing a SAML logout request. This way of communicating between the IdP and
        the client is called HTTP redirect binding.

        Inspired by: https://github.com/IdentityPython/pysaml2/blob/master/example/sp-wsgi/sp.py

        Returns:
            bytes: URL of the IdP to redirect to with a SAMLRequest parameter
        """
        logger.info("Creating SAML logout request for %s", user)
        try:
            localpart = UserID.from_string(user).localpart

            session = self._find_session_from_user(localpart)
            # The user probally logged in via m.login.password
            if session is None:
                return False
            logger.debug("Found a user session for %s: %s", localpart, session)

            # Creating a logout request through http redirect
            responses = self._saml_client.do_logout(
                session["name_id"],
                [session["entity"]],
                reason="/_matrix/client/r0/logout requested",
                expire=None,
                expected_binding=BINDING_HTTP_REDIRECT,
            )
            # We are using the first response from do_logout() because logging out
            # from multiple IdP/sources is not supported
            binding, http_info = next(iter(responses.values()))
            logger.debug("SAML binding %s, http_info %s", binding, http_info)

            for key, value in http_info["headers"]:
                if key == "Location":
                    return value

            raise RuntimeError("missing Location header")

        except Exception as e:
            raise SynapseError(
                500, "error while creating SAML logout request: %s" % (e,)
            )

    async def handle_logout_request(self, request):
        """Handle an incoming LogoutRequest to /_matrix/saml2/logout

        Implements steps 3 and 4 of the 'Single Logout Profile' specification:
        in case a client is logging out through another application (called a
        'Session Participant'), the IdP will issue a LogoutRequest to all other
        'Session Participants' including the homeserver. In that case we need to
        logout the user and respond to the IdP.

        Args:
            request (bytes): a SAML LogoutRequest from an IdP

        Returns:
            bytes: URL to redirect the client in case of success
        """
        saml_req_encoded = parse_string(request, "SAMLRequest", required=True)
        relay_state = parse_string(request, "RelayState")
        # TODO: sign LogoutRequest responses if required by the IdP
        # sign = parse_string(request, "SigAlg")
        # sign_alg = parse_string(request, "Signature")

        saml_req = self._saml_client.parse_logout_request(
            saml_req_encoded, BINDING_HTTP_REDIRECT
        )
        name_id = saml_req.message.name_id
        # Retrieve the mxid before logging out from the local SAML cache
        mxid = self._find_mxid_from_name_id(name_id)
        # Logout from the local SAML cache
        try:
            if self._saml_client.local_logout(name_id):
                status = success_status_factory()
                # Logout from matrix
                if mxid:
                    await self._logout(mxid)
            else:
                status = status_message_factory("Server error", STATUS_REQUEST_DENIED)
        except KeyError:
            status = status_message_factory("Server error", STATUS_REQUEST_DENIED)

        # Prepare SAML LogoutResponse using HTTP_REDIRECT
        response = self._saml_client.create_logout_response(
            saml_req.message, [BINDING_HTTP_REDIRECT], status
        )
        rinfo = self._saml_client.response_args(
            saml_req.message, [BINDING_HTTP_REDIRECT]
        )

        rfinal = self._saml_client.apply_binding(
            rinfo["binding"], response, rinfo["destination"], relay_state, response=True
        )

        # Return the redirect_url
        for key, value in rfinal["headers"]:
            if key == "Location":
                return value

        # this shouldn't happen!
        raise Exception("create_logout_response didn't return a Location header")

    async def handle_logout_response(self, request):
        """Handle an incoming LogoutResponse to /_matrix/saml2/logout

        Implements step 5 of the 'Single Logout Profile' specification: when
        an IdP has finished the logout process it will send a response to all session
        participants (e.g. the homeserver), through an HTTP redirect (i.e. the browser
        send the response in behalf of the IdP).

        We need to parse the response and in case of success, proceed with a logout:
        1. on our local saml cache through the use of pysaml2.local_logout().
        2. on matrix through the use of self._logout()

        Args:
            request: the incoming request from the browser, containg the IdP response
                to the logout process.
        Returns:
            bytes: None in case of success, a SynapseError otherwise.

        """
        resp_bytes = parse_string(request, "SAMLResponse", required=True)
        try:
            resp_saml = self._saml_client.parse_logout_request_response(
                resp_bytes, BINDING_HTTP_REDIRECT
            )
        except Exception as e:
            raise SynapseError(400, "Unable to parse SAML2 response: %s" % (e,))

        logger.info("Received SAML logout response %s", resp_saml)
        if STATUS_SUCCESS == resp_saml.response.status.status_code.value:
            logout_request = self._saml_client.state[resp_saml.in_response_to]
            logger.debug("Status of the SAML cached logout request %s", logout_request)
            name_id = decode(logout_request["name_id"])
            # Retrieve the mxid before logging out from the local SAML cache
            mxid = self._find_mxid_from_name_id(name_id)
            # Logout from the local SAML cache
            self._saml_client.local_logout(name_id)
            # Logout from matrix
            if mxid:
                await self._logout(mxid)
            return

        raise SynapseError(
            500,
            "Could not logout from SAML: %s" % (resp_saml.response.status.message,),
        )

    async def handle_saml_response(self, request: SynapseRequest) -> None:
        """Handle an incoming request to /_matrix/saml2/authn_response

        Args:
            request: the incoming request from the browser. We'll
                respond to it with a redirect.

        Returns:
            Completes once we have handled the request.
        """
        resp_bytes = parse_string(request, "SAMLResponse", required=True)
        relay_state = parse_string(request, "RelayState", required=True)

        # expire outstanding sessions before parse_authn_request_response checks
        # the dict.
        self.expire_sessions()

        # Pull out the user-agent and IP from the request.
        user_agent = request.requestHeaders.getRawHeaders(b"User-Agent", default=[b""])[
            0
        ].decode("ascii", "surrogateescape")
        ip_address = self.hs.get_ip_from_request(request)

        user_id, current_session = await self._map_saml_response_to_user(
            resp_bytes, relay_state, user_agent, ip_address
        )

        # Complete the interactive auth session or the login.
        if current_session and current_session.ui_auth_session_id:
            await self._auth_handler.complete_sso_ui_auth(
                user_id, current_session.ui_auth_session_id, request
            )

        else:
            await self._auth_handler.complete_sso_login(user_id, request, relay_state)

    async def _map_saml_response_to_user(
        self,
        resp_bytes: str,
        client_redirect_url: str,
        user_agent: str,
        ip_address: str,
    ) -> Tuple[str, Optional[Saml2SessionData]]:
        """
        Given a sample response, retrieve the cached session and user for it.

        Args:
            resp_bytes: The SAML response.
            client_redirect_url: The redirect URL passed in by the client.
            user_agent: The user agent of the client making the request.
            ip_address: The IP address of the client making the request.

        Returns:
             Tuple of the user ID and SAML session associated with this response.

        Raises:
            SynapseError if there was a problem with the response.
            RedirectException: some mapping providers may raise this if they need
                to redirect to an interstitial page.
        """
        try:
            saml2_auth = self._saml_client.parse_authn_request_response(
                resp_bytes,
                BINDING_HTTP_POST,
                outstanding=self._outstanding_requests_dict,
            )
        except saml2.response.UnsolicitedResponse as e:
            # the pysaml2 library helpfully logs an ERROR here, but neglects to log
            # the session ID. I don't really want to put the full text of the exception
            # in the (user-visible) exception message, so let's log the exception here
            # so we can track down the session IDs later.
            logger.warning(str(e))
            raise SynapseError(400, "Unexpected SAML2 login.")
        except Exception as e:
            raise SynapseError(400, "Unable to parse SAML2 response: %s." % (e,))

        if saml2_auth.not_signed:
            raise SynapseError(400, "SAML2 response was not signed.")

        logger.debug("SAML2 response: %s", saml2_auth.origxml)
        for assertion in saml2_auth.assertions:
            # kibana limits the length of a log field, whereas this is all rather
            # useful, so split it up.
            count = 0
            for part in chunk_seq(str(assertion), 10000):
                logger.info(
                    "SAML2 assertion: %s%s", "(%i)..." % (count,) if count else "", part
                )
                count += 1

        logger.info("SAML2 mapped attributes: %s", saml2_auth.ava)

        current_session = self._outstanding_requests_dict.pop(
            saml2_auth.in_response_to, None
        )

        for requirement in self._saml2_attribute_requirements:
            _check_attribute_requirement(saml2_auth.ava, requirement)

        remote_user_id = self._user_mapping_provider.get_remote_user_id(
            saml2_auth, client_redirect_url
        )

        if not remote_user_id:
            raise Exception("Failed to extract remote user id from SAML response")

        with (await self._mapping_lock.queue(self._auth_provider_id)):
            # first of all, check if we already have a mapping for this user
            logger.info(
                "Looking for existing mapping for user %s:%s",
                self._auth_provider_id,
                remote_user_id,
            )
            registered_user_id = await self._datastore.get_user_by_external_id(
                self._auth_provider_id, remote_user_id
            )
            if registered_user_id is not None:
                logger.info("Found existing mapping %s", registered_user_id)
                return registered_user_id, current_session

            # backwards-compatibility hack: see if there is an existing user with a
            # suitable mapping from the uid
            if (
                self._grandfathered_mxid_source_attribute
                and self._grandfathered_mxid_source_attribute in saml2_auth.ava
            ):
                attrval = saml2_auth.ava[self._grandfathered_mxid_source_attribute][0]
                user_id = UserID(
                    map_username_to_mxid_localpart(attrval), self._hostname
                ).to_string()
                logger.info(
                    "Looking for existing account based on mapped %s %s",
                    self._grandfathered_mxid_source_attribute,
                    user_id,
                )

                users = await self._datastore.get_users_by_id_case_insensitive(user_id)
                if users:
                    registered_user_id = list(users.keys())[0]
                    logger.info("Grandfathering mapping to %s", registered_user_id)
                    await self._datastore.record_user_external_id(
                        self._auth_provider_id, remote_user_id, registered_user_id
                    )
                    return registered_user_id, current_session

            # Map saml response to user attributes using the configured mapping provider
            for i in range(1000):
                attribute_dict = self._user_mapping_provider.saml_response_to_user_attributes(
                    saml2_auth, i, client_redirect_url=client_redirect_url,
                )

                logger.debug(
                    "Retrieved SAML attributes from user mapping provider: %s "
                    "(attempt %d)",
                    attribute_dict,
                    i,
                )

                localpart = attribute_dict.get("mxid_localpart")
                if not localpart:
                    raise Exception(
                        "Error parsing SAML2 response: SAML mapping provider plugin "
                        "did not return a mxid_localpart value"
                    )

                displayname = attribute_dict.get("displayname")
                emails = attribute_dict.get("emails", [])

                # Check if this mxid already exists
                if not await self._datastore.get_users_by_id_case_insensitive(
                    UserID(localpart, self._hostname).to_string()
                ):
                    # This mxid is free
                    break
            else:
                # Unable to generate a username in 1000 iterations
                # Break and return error to the user
                raise SynapseError(
                    500, "Unable to generate a Matrix ID from the SAML response"
                )

            logger.info("Mapped SAML user to local part %s", localpart)

            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart,
                default_display_name=displayname,
                bind_emails=emails,
                user_agent_ips=(user_agent, ip_address),
            )

            await self._datastore.record_user_external_id(
                self._auth_provider_id, remote_user_id, registered_user_id
            )
            return registered_user_id, current_session

    def expire_sessions(self):
        expire_before = self._clock.time_msec() - self._saml2_session_lifetime
        to_expire = set()
        for reqid, data in self._outstanding_requests_dict.items():
            if data.creation_time < expire_before:
                to_expire.add(reqid)
        for reqid in to_expire:
            logger.debug("Expiring session id %s", reqid)
            del self._outstanding_requests_dict[reqid]


def _check_attribute_requirement(ava: dict, req: SamlAttributeRequirement):
    values = ava.get(req.attribute, [])
    for v in values:
        if v == req.value:
            return

    logger.info(
        "SAML2 attribute %s did not match required value '%s' (was '%s')",
        req.attribute,
        req.value,
        values,
    )
    raise AuthError(403, "You are not authorized to log in here.")


DOT_REPLACE_PATTERN = re.compile(
    ("[^%s]" % (re.escape("".join(mxid_localpart_allowed_characters)),))
)


def dot_replace_for_mxid(username: str) -> str:
    """Replace any characters which are not allowed in Matrix IDs with a dot."""
    username = username.lower()
    username = DOT_REPLACE_PATTERN.sub(".", username)

    # regular mxids aren't allowed to start with an underscore either
    username = re.sub("^_", "", username)
    return username


MXID_MAPPER_MAP = {
    "hexencode": map_username_to_mxid_localpart,
    "dotreplace": dot_replace_for_mxid,
}  # type: Dict[str, Callable[[str], str]]


@attr.s
class SamlConfig:
    mxid_source_attribute = attr.ib()
    mxid_mapper = attr.ib()


class DefaultSamlMappingProvider:
    __version__ = "0.0.1"

    def __init__(self, parsed_config: SamlConfig, module_api: ModuleApi):
        """The default SAML user mapping provider

        Args:
            parsed_config: Module configuration
            module_api: module api proxy
        """
        self._mxid_source_attribute = parsed_config.mxid_source_attribute
        self._mxid_mapper = parsed_config.mxid_mapper

        self._grandfathered_mxid_source_attribute = (
            module_api._hs.config.saml2_grandfathered_mxid_source_attribute
        )

    def get_remote_user_id(
        self, saml_response: saml2.response.AuthnResponse, client_redirect_url: str
    ) -> str:
        """Extracts the remote user id from the SAML response"""
        try:
            return saml_response.ava["uid"][0]
        except KeyError:
            logger.warning("SAML2 response lacks a 'uid' attestation")
            raise SynapseError(400, "'uid' not in SAML2 response")

    def saml_response_to_user_attributes(
        self,
        saml_response: saml2.response.AuthnResponse,
        failures: int,
        client_redirect_url: str,
    ) -> dict:
        """Maps some text from a SAML response to attributes of a new user

        Args:
            saml_response: A SAML auth response object

            failures: How many times a call to this function with this
                saml_response has resulted in a failure

            client_redirect_url: where the client wants to redirect to

        Returns:
            dict: A dict containing new user attributes. Possible keys:
                * mxid_localpart (str): Required. The localpart of the user's mxid
                * displayname (str): The displayname of the user
                * emails (list[str]): Any emails for the user
        """
        try:
            mxid_source = saml_response.ava[self._mxid_source_attribute][0]
        except KeyError:
            logger.warning(
                "SAML2 response lacks a '%s' attestation", self._mxid_source_attribute,
            )
            raise SynapseError(
                400, "%s not in SAML2 response" % (self._mxid_source_attribute,)
            )

        # Use the configured mapper for this mxid_source
        base_mxid_localpart = self._mxid_mapper(mxid_source)

        # Append suffix integer if last call to this function failed to produce
        # a usable mxid
        localpart = base_mxid_localpart + (str(failures) if failures else "")

        # Retrieve the display name from the saml response
        # If displayname is None, the mxid_localpart will be used instead
        displayname = saml_response.ava.get("displayName", [None])[0]

        # Retrieve any emails present in the saml response
        emails = saml_response.ava.get("email", [])

        return {
            "mxid_localpart": localpart,
            "displayname": displayname,
            "emails": emails,
        }

    @staticmethod
    def parse_config(config: dict) -> SamlConfig:
        """Parse the dict provided by the homeserver's config
        Args:
            config: A dictionary containing configuration options for this provider
        Returns:
            SamlConfig: A custom config object for this module
        """
        # Parse config options and use defaults where necessary
        mxid_source_attribute = config.get("mxid_source_attribute", "uid")
        mapping_type = config.get("mxid_mapping", "hexencode")

        # Retrieve the associating mapping function
        try:
            mxid_mapper = MXID_MAPPER_MAP[mapping_type]
        except KeyError:
            raise ConfigError(
                "saml2_config.user_mapping_provider.config: '%s' is not a valid "
                "mxid_mapping value" % (mapping_type,)
            )

        return SamlConfig(mxid_source_attribute, mxid_mapper)

    @staticmethod
    def get_saml_attributes(config: SamlConfig) -> Tuple[Set[str], Set[str]]:
        """Returns the required attributes of a SAML

        Args:
            config: A SamlConfig object containing configuration params for this provider

        Returns:
            The first set equates to the saml auth response
                attributes that are required for the module to function, whereas the
                second set consists of those attributes which can be used if
                available, but are not necessary
        """
        return {"uid", config.mxid_source_attribute}, {"displayName", "email"}
