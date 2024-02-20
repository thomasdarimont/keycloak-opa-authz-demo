package keycloak.realms.opademo.access

#https://www.openpolicyagent.org/docs/latest/policy-testing/

import future.keywords.if
import future.keywords.in

import data.keycloak.utils.kc

test_access_account_console if {
    allow with input as {
                          "subject": {
                            "username": "tester",
                            "realmRoles": [ "user" ]
                          },
                          "resource": {
                            "realm": "opademo",
                            "clientId": "account-console"
                          }
                        }
}

test_access_app1 if {
        allow with input as {
                              "subject": {
                                "username": "tester",
                                "clientRoles": [ "app1:access" ]
                              },
                              "resource": {
                                "realm": "opademo",
                                "clientId": "app1"
                              }
                            }
}