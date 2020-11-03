-- Authentication based on a HMAC verification of the room name
-- Config params:
-- logineo_hmac_secret: base64-encoded shared HMAC secret
-- logineo_session_timeout: Maximum age of the token in seconds
-- This file must be copied to /usr/lib/prosody/modules/mod_auth_logineo.lua
-- This modules depends on basexx.

local formdecode = require "util.http".formdecode;
local generate_uuid = require "util.uuid".generate;
local new_sasl = require "util.sasl".new;
local sasl = require "util.sasl";
local sessions = prosody.full_sessions;
local basexx = require "basexx";
local os = require "os";
local hmac = require "util.hmac";

-- Ensure configured
local hmac_secret_base64 = module:get_option("logineo_hmac_secret", nil);
if hmac_secret_base64 == nil then
    module:log("warn", "Missing 'hmac_secret' config, not configuring logineo auth");
    return;
end

local hmac_secret = basexx.from_base64(hmac_secret_base64)

local session_timeout_str = module:get_option("logineo_session_timeout", nil);
if session_timeout_str == nil then
    module:log("warn", "Missing 'logineo_session_timeout' config, not configuring logineo auth");
    return;
end

local session_timeout = tonumber(session_timeout_str)

-- define auth provider
local provider = {};

local host = module.host;

-- Extract room name param from URL when session is created
function init_session(event)
	local session, request = event.session, event.request;
	local query = request.url.query;

	if query ~= nil then
           local params = formdecode(query);
           -- The room name
           session.room = params.room;
       end
end

-- Might be changed module:hook_global when ran as a plug-in
module:hook("bosh-session", init_session);
module:hook("websocket-session", init_session);

function provider.test_password(username, password)
	return nil, "Password based auth not supported";
end

function provider.get_password(username)
	return nil;
end

function provider.set_password(username, password)
	return nil, "Set password not supported";
end

function provider.user_exists(username)
	return nil;
end

function provider.create_user(username, password)
	return nil;
end

function provider.delete_user(username)
	return nil;
end

local function get_int_from_bigendian_bytes(str)
   local len = string.len(str)
   local value = 0
   for i = 1, len, 1 do
      value = value + string.byte(str, i) * ( 2 ^ ( ( len - i ) * 8 ) )
   end
   return value
end


local function verify_room_id(session)
    if session.room == nil then
        return false, "bad-request", "No room name found in session";
    end
    
    local token = session.room
    if string.len(token) < 60 then
        return false, "bad-request", "Invalid session token";
    end

    local encodedHash = string.sub(token, -52)
    local decodedHash = basexx.from_base32(encodedHash)

    local str = string.lower(string.sub(token, 0, -53))
    local hash = hmac.sha256(hmac_secret, str, false)

    if (hash == decodedHash) then
       local encodedStamp = string.sub(token, -59, -53)
       local stamp = basexx.from_base32(encodedStamp)
       local diff = os.time() - get_int_from_bigendian_bytes(stamp)
       if diff > session_timeout then
       	   log("warn", "Session token " .. token .. " has expired (age: " .. diff .. "s)");
       	   return false, "access-denied", "Session has expired"
       end
       return true
    end

    return false, "access-denied", "Hash mismatch"
end

function provider.get_sasl_handler(session)

	local function get_username_from_token(self, message)
		local res, error, reason = verify_room_id(session);

		if (res == false) then
		    log("warn", "Authentication failed:%s, reason:%s", error, reason);
		    session.auth_token = nil;
		    return res, error, reason;
		end

		local customUsername
		    = prosody.events.fire_event("pre-jitsi-authentication", session);

		log("warn", "Custom username: %s", customUsername);

		if (customUsername) then
		    self.username = customUsername;
		elseif (session.previd ~= nil) then
		    for _, session1 in pairs(sessions) do
		        if (session1.resumption_token == session.previd) then
		            self.username = session1.username;
		            break;
		        end
			end
		else
		    self.username = message;
		end
		log("warn", "self.username: %s", self.username);

		return res;
	end

	return new_sasl(host, { anonymous = get_username_from_token });
end

module:provides("auth", provider);

local function anonymous(self, message)

	local username = generate_uuid();

	-- This calls the handler created in 'provider.get_sasl_handler(session)'
	local result, err, msg = self.profile.anonymous(self, username, self.realm);

	if result == true then
		if (self.username == nil) then
			self.username = username;
		end
		return "success";
	else
		return "failure", err, msg;
	end
end

sasl.registerMechanism("ANONYMOUS", {"anonymous"}, anonymous);
