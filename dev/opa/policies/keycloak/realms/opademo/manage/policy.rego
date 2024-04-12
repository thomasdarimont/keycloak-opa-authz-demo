package keycloak.realms.opademo.manage

import rego.v1

import data.keycloak.utils.kc

# Access Policy: Default
# Default allow rule: deny all
default allow := false

# Resource Policy: Allow admins
allow if {
	kc.hasRealmRole("admin")
}

# Resource Policy: Allow customer admins to manage their groups
allow if {
	kc.hasRealmRole("customer-admin")
	input.resource.resourcePath == "/customers"
}

# Resource Policy: Allow customer admins to manage their groups
allow if {
	kc.hasRealmRole("customer-admin")
	some group in input.subject.groups
	input.resource.resourcePath == concat("", ["/customers/", group])
}
