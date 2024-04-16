package keycloak.realms.opademo.access

import rego.v1

import data.keycloak.utils.kc

# Access Policy: Default
# Default allow rule: deny all
default allow := false


# Access Policy: Authentication
allow if{
	kc.isClient("Apisix")
	kc.isProtocol("openid-connect")
	kc.isRealm("opademo")
	kc.isGrantType("password")
	kc.hasRealmRole("admin")
}

# Access Policy: Onboard
allow if {
	input.resource.resourcePath == "opademo/clients/168609d0-a202-4355-a081-04b03b13b9aa"
	kc.isRealm("opademo")
	kc.isClient("Apisix")
  	kc.hasRealmRole("admin")
	input.subject.username == "data_product_owner"
}

# Access Policy: Account-Console
# Allow access to client-id:account-console if realm-role:user
allow if {
	kc.isClient("account-console")
	kc.hasRealmRole("user")
}

# Access Policy: App1
# Allow access to client-id:app1 if client-role:access
allow if {
	kc.isClient("app1")
	kc.hasClientRole("app1", "access")
}

# Access Policy: App2
# Allow access to client-id:app2 if client-role:access
allow if {
	kc.isClient("app2")
	kc.hasCurrentClientRole("access")
}

# Access Policy: App3
# Allow access to client-id:app3 if member of group
allow if {
	kc.isClient("app3")
	kc.isGroupMember("Users")
}

# Access Policy: "Special Clients"
# Allow access to a set of "special clients" if member of group FooBar
allow if {
	is_special_client(input.resource.clientId)
	kc.isGroupMember("FooBar")
}

# Access Policy: "app6-check-network"
# Allow access to client based on remote network address (Forwarded header)
allow if {
	kc.isClient("app6-check-network")

	# "172.18.0.1/16"
	# 172.20.0.1/16
	kc.isFromNetwork("172.99.0.1/16")
}

# Access Policy: "app7-password-grant"
# Allow usage of password grant only for this client
allow if {
	kc.isClient("app7-password-grantXXX")
	kc.isProtocol("openid-connect")
	kc.isGrantType("password")
}

# Access Policy: "app8-client-credentials"
# Allow usage of client_credentials grant only for this client
allow if {
	kc.isClient("app8-client-credentialsXXX")
	kc.isProtocol("openid-connect")
	kc.isGrantType("client_credentials")
}

# client ends with "-foo" or "-bar"
is_special_client(clientId) if endswith(clientId, "-foo")

is_special_client(clientId) if endswith(clientId, "-bar")

# use with is_account_client(input.resource.clientId)
is_account_client(clientId) if clientId in ["account", "account-console"]

# https://www.styra.com/blog/how-to-express-or-in-rego/
