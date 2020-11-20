#!/usr/bin/python3

import logging
from twisted.internet import defer
import requests
import base64
import hmac
from hashlib import sha256
import re
import time

logger = logging.getLogger(__name__)
room_id_pattern = re.compile('!([^:]+)')

def clone_dict(dict):
    clone = {}
    for key, value in dict.items():
        clone[key] = value
    return clone

class LogineoRules:

	def __init__(self, config, module_api):
		self.config = config
		self.http_client = module_api.http_client

	def get_privileges(self, user_id):
		return self.http_client.get_json(self.config["endpoint_url"], headers={"Authenticated-User": [user_id]})

	def generate_conference_id_token(self, room_id):
		room_id_match = room_id_pattern.match(room_id)
		if room_id_match:
			room_id = room_id_match.group(1)
		epoch = int(time.time())
		epoch_bytes = epoch.to_bytes(4, byteorder='big')
		epoch_base32 = base64.b32encode(epoch_bytes).decode()[:7].lower()
		conference_id = room_id.lower() + epoch_base32
		hmac_bytes = hmac.new(key=self.config["jitsi_hmac_secret"], msg=conference_id.encode('utf-8'), digestmod=sha256).digest()
		return conference_id + base64.b32encode(hmac_bytes).decode()[:-4].lower()

	def sanitize_jitsi_event(self, event):
		conference_id = self.generate_conference_id_token(event["room_id"])
		content = event["content"]
		url = content["url"];
		url = re.sub(r'conferenceId=[^&]+', "conferenceId=" + conference_id, url)
		url = re.sub(r'confId=[^#&]+', "confId=" + conference_id, url)
		url = re.sub(r'conferenceDomain=[^#&]+', "conferenceDomain=" + self.config["jitsi_domain"], url)
		new_content = clone_dict(content)
		new_content["url"] = url
		new_data = clone_dict(content["data"])
		new_data["conferenceId"] = conference_id
		new_data["domain"] = self.config["jitsi_domain"]
		new_content["data"] = new_data
		new_event = clone_dict(event)
		new_event["content"] = new_content
		return new_event

	async def check_event_allowed(self, event, state_events):
		allowed = True
		content = event["content"]
		if event.type == "m.room.member":
			if content["membership"] == "invite" and not ("is_direct" in content and content["is_direct"]):
				privileges = await self.get_privileges(event.sender)
				allowed = "create-rooms" in privileges
		elif event.type == "im.vector.modular.widgets":
			if "type" in content and content["type"] == "jitsi":
				privileges = await self.get_privileges(event.sender)
				allowed = "start-conference" in privileges
				if allowed:
					return self.sanitize_jitsi_event(event)

		return allowed

	async def on_create_room(self, requester, config, is_requester_admin):
		allowed = False
		user_id = requester.user.to_string()
		privileges = await self.get_privileges(user_id)

		if "create-rooms" in privileges:
			allowed = True
		elif "is_direct" in config and config["is_direct"] and "create-direct-rooms" in privileges:
			invitee = config["invite"][0]
			checkUrl = self.config["endpoint_url"] + "/create-direct-rooms/check"
			check = await self.http_client.get_json(checkUrl, args={"subject": invitee}, headers={"Authenticated-User": [user_id]})
			allowed = check["allowed"]

		return allowed

	def check_threepid_can_be_invited(self, medium, address, state_events):
		return True

	def parse_config(config):
		endpoint_url = config.get("endpoint_url")
		jitsi_hmac_secret = base64.b64decode(config.get("jitsi_hmac_secret"))
		jitsi_domain = config.get("jitsi_domain")
		return { "endpoint_url": endpoint_url, "jitsi_hmac_secret": jitsi_hmac_secret, "jitsi_domain": jitsi_domain }


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


