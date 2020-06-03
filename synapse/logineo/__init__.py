#!/usr/bin/python3

import logging
from twisted.internet import defer

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


