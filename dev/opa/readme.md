Open Policy Agent Policies
---

## Testing OPA Policies

```
opa test ./policies -v
```

Example run:
```
$ opa test ./policies -v
policies/keycloak/realms/opademo/access/policy_test.rego:
data.keycloak.realms.opademo.access.test_access_account_console: PASS (328.491µs)
data.keycloak.realms.opademo.access.test_access_app1: PASS (488.76µs)
--------------------------------------------------------------------------------
PASS: 2/2
```
