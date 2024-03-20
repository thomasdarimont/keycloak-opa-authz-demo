Keycloak Open Policy Integration Demo
----

Example code for integrating Open Policy Agent with Keycloak presented at Keycloak Dev Day 2024.

[Slides](keycloak-devday-2024-flexible-authz-for-keycloak-with-openpolicyagent.pdf)

# Run

## Run with HTTP

Start the docker compose setup with Keycloak, Open Policy Agent, Mail server.

```
docker compose -f dev/docker-compose.yml up
```

## Run with HTTPS

This example uses https://id.kubecon.test:8443/auth as the Keycloak auth server URL.

To use the example with https just add a mapping for `id.kubecon.test` to your `/etc/hosts` file
and regenerate the certificates via the [mkcert](https://github.com/FiloSottile/mkcert) tool first.

Then start the `dev/docker-compose-https.yml` docker compose file.

´´´
(cd dev/config/certs && mkcert -install && mkcert -cert-file kubecon.pem -key-file kubecon-key.pem "*.kubecon.test")

docker compose -f dev/docker-compose-https.yml up
´´´

# Demo

Once up, you can access Keycloak via http://localhost:8080/auth and login with `admin/admin`.

The demo contains a realm called `opademo` that is configured via `dev/config/realms/opademo.yaml`
through [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli).

## Users

The example contains a few users to demonstrate various aspects.

- Username: "tester" with Password: "test"
- Username: "admin" with Password: "test"
- Username: "guest" with Password: "test"

## Clients

The `opademo` realm contains a few client applications to demonstrate various access policies expressed
with the REGO Policy language provided by OpenPolicyAgent. 

## OPA Access Policy

The client access policies are defined in the file `dev/opa/policies/keycloak/realms/opademo/access/policy.rego`. 
For this demo Open Policy Agent is configured to watch the file for changes and will automatically
update the policies on change.

To enable the policy check, go to `opademo Realm` -> `Authentication` -> `Required Actions` -> `Enable: OPA Policy Check`.

## Realm configuration

The realm with the clients, roles, groups and users are defined in the `dev/config/realms/opademo.yaml` 
config file. 

For the demo the `tester` user can be granted more access incrementally by uncommenting the role / group memeber ship mapping in the `opademo.yaml` file.

To apply the changed realm configuration to the running Keycloak instance, just execute the following command:

`docker restart dev-keycloak-provisioning-1`.