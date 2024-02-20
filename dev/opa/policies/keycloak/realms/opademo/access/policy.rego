package keycloak.realms.opademo.access

# import rego.v1
import future.keywords.if
import future.keywords.in

import data.keycloak.utils.kc

# default allow rule: deny all
default allow := false

# allow access to client-id:account-console if realm-role:user
allow if {
	kc.isClient("account-console")
	kc.hasRealmRole("user")
}

# allow access to client-id:app1 if client-role:access
allow if {
	kc.isClient("app1")
	kc.hasClientRole("app1", "access")
}

# allow access to client-id:app2 if client-role:access
allow if {
	kc.isClient("app2")
	kc.hasCurrentClientRole("access")
}

# allow access to client-id:app3 if member of group
allow if {
	kc.isClient("app3")
	kc.isGroupMember("Users")
}

# allow access to "special clients" if member of group
allow if {
	is_special_client(input.resource.clientId)
	kc.isGroupMember("FooBar")
}

# allow access to client based on remote network address (Forwarded header)
allow if {
	kc.isClient("app6-check-network")
	# "172.18.0.1/16"
	kc.isFromNetwork("172.17.0.1/16")
}

allow if {
    kc.isClient("app7-password-grant")
    kc.isProtocol("openid-connect")
    kc.isGrantType("password")
}

allow if {
    kc.isClient("app8-client-credentials")
    kc.isProtocol("openid-connect")
    kc.isGrantType("client_credentials")
}

# client ends with "-foo" or "-bar"
is_special_client(clientId) if endswith(clientId, "-foo")
is_special_client(clientId) if endswith(clientId, "-bar")

# use with is_account_client(input.resource.clientId)
is_account_client(clientId) if clientId = "account"
is_account_client(clientId) if clientId = "account-console"

# https://www.styra.com/blog/how-to-express-or-in-rego/
