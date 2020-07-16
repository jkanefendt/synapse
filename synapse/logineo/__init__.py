#!/usr/bin/python3

import logging
from twisted.internet import defer
import requests
import json

logger = logging.getLogger(__name__)

class LogineoRules:

	def __init__(self, config, http_client):
		self.config = config
		self.http_client = http_client

	@defer.inlineCallbacks
	def get_privileges(self, user_id):
		privileges = yield self.http_client.get_json(self.config["endpoint_url"], headers={"Authenticated-User": [user_id]})
		defer.returnValue(privileges)

	@defer.inlineCallbacks
	def check_event_allowed(self, event, state_events):
		allowed = True
		if event.type == "m.room.member":
			content = event["content"]
			if content["membership"] == "invite" and not ("is_direct" in content and content["is_direct"]):
				privileges = yield self.get_privileges(event.sender)
				allowed = "create-rooms" in privileges

		defer.returnValue(allowed)

	@defer.inlineCallbacks
	def on_create_room(self, requester, config, is_requester_admin):
		allowed = False
		user_id = requester.user.to_string()
		privileges = yield self.get_privileges(user_id)

		if "create-rooms" in privileges:
			allowed = True
		elif "is_direct" in config and config["is_direct"] and "create-direct-rooms" in privileges:
			invitee = config["invite"][0]
			checkUrl = self.config["endpoint_url"] + "/create-direct-rooms/check"
			check = yield self.http_client.get_json(checkUrl, args={"subject": invitee}, headers={"Authenticated-User": [user_id]})
			allowed = check["allowed"]

		defer.returnValue(allowed)

	@defer.inlineCallbacks
	def check_threepid_can_be_invited(self, medium, address, state_events):
		defer.returnValue(True)

	def parse_config(config):
		endpoint_url = config.get("endpoint_url")
		return { "endpoint_url": endpoint_url }


class RestAuthProvider(object):

    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        if not config.endpoint:
            raise RuntimeError('Missing endpoint config')

        self.endpoint = config.endpoint
        self.config = config

        logger.info('Endpoint: %s', self.endpoint)

    @defer.inlineCallbacks
    def check(self, data):
        r = requests.post(self.endpoint + '/_matrix-internal/identity/v1/check_credentials', json = data)
        r.raise_for_status()
        r = r.json()
        if not r["auth"]:
            reason = "Invalid JSON data returned from REST endpoint"
            logger.warning(reason)
            raise RuntimeError(reason)

        auth = r["auth"]
        if not auth["success"]:
            logger.info("User not authenticated")
            defer.returnValue(False)

        user_id = auth["mxid"]

        localpart = user_id.split(":", 1)[0][1:]
        logger.info("User %s authenticated", user_id)

        registration = False
        if not (yield self.account_handler.check_user_exists(user_id)):
            logger.info("User %s does not exist yet, creating...", user_id)
            user_id, access_token = (yield self.account_handler.register(localpart=localpart))
            registration = True
            logger.info("Registration based on REST data was successful for %s", user_id)
        else:
            logger.info("User %s already exists, registration skipped", user_id)

        if auth["profile"]:
            logger.info("Handling profile data")
            profile = auth["profile"]

            store = yield self.account_handler._hs.get_profile_handler().store
            if "display_name" in profile:
                display_name = profile["display_name"]
                logger.info("Setting display name to '%s' based on profile data", display_name)
                yield store.set_profile_displayname(localpart, display_name)
            else:
                logger.info("Display name was not set because it was not given or policy restricted it")
        else:
            logger.info("No profile data")

        defer.returnValue(user_id)

    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        logger.info("Got password check for " + user_id)
        data = {'user':{'id':user_id, 'password':password}}

        success = yield self.check(data)
        defer.returnValue(success)

    @defer.inlineCallbacks
    def check_3pid_auth(self, medium, address, password):
        logger.info("Got 3pid check for address " + address + ", medium " + medium)
        data = {'user':{'three_pid': {'address': address, 'medium': medium}, 'password':password}}

        success = yield self.check(data)
        defer.returnValue(success)

    @staticmethod
    def parse_config(config):
        class _RestConfig(object):
            endpoint = ''

        rest_config = _RestConfig()
        rest_config.endpoint = config["endpoint"]

        return rest_config


