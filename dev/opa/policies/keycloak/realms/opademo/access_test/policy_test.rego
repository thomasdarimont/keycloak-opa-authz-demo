package keycloak.realms.opademo.access_test

# See https://www.openpolicyagent.org/docs/latest/policy-testing/
import rego.v1

import data.keycloak.realms.opademo.access

test_access_account_console if {
	access.allow with input as {
		"subject": {"username": "tester", "realmRoles": ["user"]},
		"resource": {"realm": "opademo", "clientId": "account-console"},
	}
}

test_access_app1 if {
	access.allow with input as {
		"subject": {"username": "tester", "clientRoles": ["app1:access"]},
		"resource": {"realm": "opademo", "clientId": "app1"},
	}
}
