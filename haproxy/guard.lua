local _M = {}

local json = require("rxi-json-lua")
local jwt = require "jwt"
local redis = require "redis"
local socket= require("socket")
local crypto = require("crypto")
require("print_r")

local redis_host = os.getenv("REDIS_HOST");
local redis_port = os.getenv("REDIS_PORT");
local redis_ip = socket.dns.toip(redis_host)
local public_key = crypto.pkey.read("/key/public.pem")
local private_tmp_key = crypto.pkey.read("/key/private_tmp.pem", true)
local public_tmp_key = crypto.pkey.read("/key/public_tmp.pem")

function _M.hello_world(applet)
  applet:set_status(200)
  local response = string.format([[<html><body>Hello World!</body></html>]], message);
  applet:add_header("content-type", "text/html");
  applet:add_header("content-length", string.len(response))
  applet:start_response()
  applet:send(response)
end

function _M.send_response(applet, status, message)
  applet:set_status(status)
  local response
  if type(message) == "string" then
    response = string.format([[<html><body>%s</body></html>]], message);
    applet:add_header("content-type", "text/html");
  else
    response = json.encode(message)
    applet:add_header("content-type", "application/json")
  end
  applet:add_header("content-length", string.len(response))
  applet:start_response()
  applet:send(response)
end

function _M.validate_token_action(txn)
  local auth_header = core.tokenize(txn.sf:hdr("Authorization"), " ")
  if auth_header[1] ~= "Bearer" or not auth_header[2] then
    return txn.set_var(txn, "txn.not_authorized", true);
  end
  local claim = jwt.decode(auth_header[2],{alg="RS256",keys={public=public_key}});
  if not claim then
    return txn.set_var(txn, "txn.not_authorized", true);
  end
  if claim.exp < os.time() then
    return txn.set_var(txn, "txn.authentication_timeout", true);
  end
  txn.set_var(txn, "txn.jwt_authorized", true);
end

function _M.validate_token_fetches(txn)
  local auth_header = core.tokenize(txn.sf:hdr("Authorization"), " ")
  if auth_header[1] ~= "Bearer" or not auth_header[2] then
    return "not_authorized";
  end
  local claim = jwt.decode(auth_header[2],{alg="RS256",keys={public=public_key}});
  if not claim then
    return "not_authorized";
  end
  if claim.exp < os.time() then
    return "authentication_timeout";
  end
  return "jwt_authorized:" .. claim.jti;
end

function _M.validate_token_converter(auth_header_string)
  local auth_header = core.tokenize(auth_header_string, " ")
  if auth_header[1] ~= "Bearer" or not auth_header[2] then
    return "not_authorized";
  end
  local claim = jwt.decode(auth_header[2],{alg="RS256",keys={public=public_key}});
  if not claim then
    return "not_authorized";
  end
  if claim.exp < os.time() then
    return "authentication_timeout";
  end
  return "jwt_authorized";
end

function _M.validate_body_fetches(txn, keys_string)
  local keys = json.decode(keys_string)
  local body = txn.f:req_body();
  status, data = pcall(json.decode, body);
  if not (status and type(data) == "table") then
    return txn.set_var(txn, "txn.bad_request", true);
  end
  local key = "validate:body"
  for i, name in pairs(keys) do
    if data[name] == nil or data[name] == "" then
      return txn.set_var(txn, "txn.bad_request", true);
    end
    key = key .. ":" .. name .. ":" .. data[name]
  end
  return key;
end

function _M.validate_body(txn, keys, ttl, count, ip)
  local body = txn.f:req_body();
  status, data = pcall(json.decode, body);
  if not (status and type(data) == "table") then
    return txn.set_var(txn, "txn.bad_request", true);
  end
  local redis_key = "validate:body"
  for i, name in pairs(keys) do
    if data[name] == nil or data[name] == "" then
      return txn.set_var(txn, "txn.bad_request", true);
    end
    redis_key = redis_key .. ":" .. name .. ":" .. data[name]
  end
  if (ip) then
    redis_key = redis_key .. ":ip:" .. ip
  end
  local test = _M.redis_incr(txn, redis_key, ttl, count);
end

function _M.redis_incr(txn, key, ttl, count)
  local prefixed_key = "mobile:guard:" .. key
  local tcp = core.tcp();
  if tcp == nil then
    return false;
  end
  tcp:settimeout(1);
  if tcp:connect(redis_ip, redis_port) == nil then
    return false;
  end
  local client = redis.connect({socket=tcp});
  local status, result = pcall(client.set, client, prefixed_key, "0", "EX", ttl, "NX");
  status, result = pcall(client.incrby, client, prefixed_key, 1);
  tcp:close();
  if tonumber(result) > count + 0.1 then
    txn.set_var(txn, "txn.too_many_request", true)
    return false;
  else
    return true;
  end
end

return _M
