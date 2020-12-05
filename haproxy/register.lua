package.path = package.path  .. "./?.lua;/usr/local/etc/haproxy/?.lua"

local guard = require("guard")

core.register_service("hello-world", "http", guard.hello_world);

core.register_action("validate-token", { "http-req" }, function(txn)
  guard.validate_token_action(txn);
end);

core.register_fetches("validate-token", guard.validate_token_fetch);

core.register_converters("validate-token-converter", guard.validate_token_converter);

core.register_action("validate-body", { "http-req" }, function(txn)
  guard.validate_body(txn, {"name"}, 10, 2);
end);

core.register_fetches("validate-body", guard.validate_body_fetch);

core.register_service("status400", "http", function(applet)
  guard.send_response(applet, 400, {message="Bad Request"});
end);

core.register_service("status401", "http", function(applet)
  guard.send_response(applet, 401, {message="Not Authorized"});
end);

core.register_service("status419", "http", function(applet)
  guard.send_response(applet, 419, {message="Authentication Timeout"});
end);

core.register_service("status429", "http", function(applet)
  guard.send_response(applet, 429, {message="Too Many Requests"});
end)
