## 1. Overview

### 1.1. How does Kubernetes integration with Conjur using JWT work?

The Kubernetes cluster API implements an OpenID Connect authentication (OIDC) endpoint at `https://<cluster-url>/.well-known/openid-configuration`
- Service accounts are issued with ServiceAccount tokens, which are in JSON Web Token (JWT) format
- Pods of Deployments can be associated with a ServiceAccount and are issued JWTs via [downward API](https://kubernetes.io/docs/concepts/workloads/pods/downward-api/)
  - Example JWT:
    ```json
    {
      "aud": [
        "https://conjur.vx/"
      ],
      "exp": 1693376769,
      "iat": 1693370769,
      "iss": "https://kubernetes.default.svc.cluster.local",
      "kubernetes.io": {
        "namespace": "app-cje",
        "pod": {
          "name": "p2f-68db995878-7hg8n",
          "uid": "861be607-ff6f-4bb6-850b-42b842e44a33"
        },
        "serviceaccount": {
          "name": "p2f",
          "uid": "ddb1ca36-0231-4ecc-81b8-25fd0d11a087"
        }
      },
      "nbf": 1693370769,
      "sub": "system:serviceaccount:app-cje:p2f"
    }
    ```
- The public keys of the JSON Web Key Set (JWKS) on the authentication endpoint can be used to validate the tokens
  - The public keys of the JWKS can be retrieve by running: `kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri')`
  - Example JWKS:
    ```json
    {
      "keys":[
        {
          "use":"sig",
          "kty":"RSA",
          "kid":"qgR3hxR6c9ortKnfd96TK8FfasK-L77vRoPtVz1z91o",
          "alg":"RS256",
          "n":"462bF75dDmlqY-PaVRTVpMkIQwIEakzt1MfKGXqbCGJRNYDbY4KRbn0aO5FcFv2-zgROmYVs5QJluCCUwrZ0odCX3GzhgdupRBENOnCI8E7_-Xg4AqT6uhjoV5tQWm0yJGxOw4WfXtAImkI0-RufQMRPPbJMVHyPBE_fSXCevaeoPo3QX_zniFcQiPBQpu9ONDLgGfS3zO7rc-Of8XXozpKGNImUxrUKFOtZADtpAgdzd392SNXItxuBzov8UavcwcvJdvGlKN0G_WIiBOzS88w5EvoOYMtDH8c_LeCB0qG6EPgNpPhIdicgfmj2aLkT25ALoXK1z3B7f13zMP5nHw",
          "e":"AQAB"
        }
      ]
    }
    ```

Ref: https://kubernetes.io/docs/reference/access-authn-authz/authentication/

Conjur leverages on the Kubernetes OIDC authentication endpoint as an Identity Provider (IdP) to authenticate workloads
- Validity of the JWTs can be verified against the JWKS
- Claims in the JWTs can be verified against configured host annotations for authorization checks

![overview](https://github.com/joetanx/conjur-k8s/assets/90442032/75398653-810c-44f1-b5b9-e82e8cc0b965)

## 2. Setting up the integration

### 2.1. Lab details

#### Software Versions

- RHEL 9.2
- Kubernetes 1.28

#### Servers

|Hostname|Role|
|---|---|
|mysql.vx|MySQL server|
|kube.vx|Single-node Kubernetes cluster|

### 2.2. Kubernetes cluster

- This demo should work with any flavour of Kubernetes clusters (On-prem, AKS, EKS), but was tested with a single-node on-prem Kubernetes cluster in my lab
- For a guide to setup a single-node on-prem Kubernetes cluster: <https://github.com/joetanx/setup/blob/main/cri-o-kube.md>

### 2.3. Setup MySQL database

- Setup MySQL database according to this guide: <https://github.com/joetanx/setup/blob/main/mysql.md>

### 2.4. Login to Conjur Cloud

> [!Note]
> 
> This can be performed on any machine (including Windows and macOS)
> 
> The login procedure below was performed from the single-node Kubernetes cluster

Download the Conjur Cloud CLI package from [CyberArk Marketplace](https://cyberark-customers.force.com/mplace/s/#software)

Unpack and set executable permission:

```console
tar xvf conjurcloudcli-rhel8-Rls-v1.0.5.tar -C /usr/local/bin/
chmod +x /usr/local/bin/conjur
```

Initialize the CLI

```console
[root@foxtrot ~]# conjur init
Enter the URL of your Conjur Cloud (use the following format: https://<subdomain>.secretsmgr.cyberark.cloud/api): https://apj-secrets.secretsmgr.cyberark.cloud/api
Configuration written to /root/.conjurrc

Successfully initialized the Conjur Cloud CLI
To start using the Conjur Cloud CLI, log in to the Conjur Cloud by running `conjur login`
```

The `.conjurrc` file created by `conjur init` is the metadata of the Conjur Cloud tenant

```console
[root@foxtrot ~]# cat .conjurrc
---
cert_file: ''
conjur_account: conjur
conjur_url: https://apj-secrets.secretsmgr.cyberark.cloud/api
identity_url: https://aap4062.id.cyberark.cloud
```

Login to Conjur Cloud:

```console
[root@foxtrot ~]# conjur login
Enter your username: joe.tan@cyberark.cloud.1234
Enter your password or API key (this will not be echoed):
Choose your secondary authentication method:
(1) Send email with a one-time code to xxxx@cyberark.com
(2) Send text with a one-time code to XXX-1234
Type your selection: 1
A one-time code has been sent to the method of your choice. Enter the one-time code that you received:
86990157
WARNING: No supported keystore found! Saving Conjur Cloud token in '/root/.conjur_credentials'. Make sure to logoff after you have finished using the CLI
Successfully logged in to Conjur Cloud
```

The login writes a short-lived access token to `.conjur_credentials`

```console
[root@foxtrot ~]# cat .conjur_credentials
{"machine": "https://apj-secrets.secretsmgr.cyberark.cloud/api", "username": "joe.tan@cyberark.cloud.3434", "password": null, "api_key": null, "api_token": "{\"protected\":\"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiJkZDkzZjhkNjNmYjE4OGZhMWMxYjllOWU1ZDJiMzFjYWFjNDkwZmY5ODBhNDhjNzI0OTdmYzhjMzI2MjJhNTUyIn0=\",\"payload\":\"eyJzdWIiOiJqb2UudGFuQGN5YmVyYXJrLmNsb3VkLjM0MzQiLCJleHAiOjE2ODQ4NTEwNjUsImlhdCI6MTY4NDg0NzQ2NX0=\",\"signature\":\"ncNTktNwrHRoYUF7HlOTnMjCjsuaU1kPyYAvrt41_VPm7I1hsmHZTKieVEUvoUYEFDlQCjmmOiCRoinfJfF4HwzkEVNkJQNtmHref8dbQzJiT_tz2poGMoGs0S-Zp1zT0caSHl6KkdEQhXKL6C-hlYqPCz7j-MRjNaSPI66Hjp9QV_TQW2vkvZdBydj5uj6qcOEmHA8uusLcfpvXpaOhjSm9ZkFmV_mH8jjgTzyyXLbQC7DDX5HRo0CiylJYc4yYwiePsP9ajLnAtw1oB2TmvZ2R2jFpMuvdTNRaFVCJoA-NEBfs6-zXhDwxeVUn3k6jpX6Cx6ay6KELeQwnqdCEjthLkV8-3SAFJgDzJ_efP8Ca1dgiXDmehE_M_5dYoiNV\"}", "api_token_expiration": "2023-05-23 22:08:05"}
```

## 3. Prepare Conjur configurations

> [!Important]
> 
> Policies on Conjur Cloud are segregated into `data` and `conjur` branches:
> - `data` are meant for resources (e.g. hosts, groups, variables)
>  - The sub-policy `data/vault` contains secrets synchronized from Privilege Cloud
> - `conjur` holds the authencator services
> 
> Ref: https://docs.cyberark.com/Product-Doc/OnlineHelp/ConjurCloud/Latest/en/Content/ConjurCloud/cl_policytree.htm

There are 3 Conjur policies provider in the [`policies`](./policies) directory of this repository: `app-vars.yaml`, `authn-jwt-k8s.yaml` and `k8s-hosts.yaml`

> [!Note]
> 
> The policy examples provided in this repository uses a `jtan` prefix
> 
> Edit the prefix to your desired name before loading them

### 3.1. Secrets policy

`app-vars.yaml` contains the `jtan/db_cityapp` policy which defines:
- variables `address`, `username` and `password` for the database credentials
- group `consumers` that is used to allow host identities access to the variables

Download the example file and load to the `data` branch:

```console
curl -sLO https://github.com/joetanx/cjc-k8s/raw/main/policies/app-vars.yaml
conjur policy load -b data -f app-vars.yaml
```

Populate the database credentials for this Kubernetes integration

```console
conjur variable set -i data/jtan/db_cityapp/address -v mysql.vx
conjur variable set -i data/jtan/db_cityapp/username -v cityapp
conjur variable set -i data/jtan/db_cityapp/password -v Cyberark1
```

### 3.2. Host identity policy

`k8s-hosts.yaml` defines `jtan/k8s` policy with:

- Demo applications
  |Host identity|Service account|
  |---|---|
  |`p2f`|`system:serviceaccount:app-cjc:p2f`|
  |`p2s-env`|`system:serviceaccount:app-cjc:p2s-env`|
  |`p2s-vol`|`system:serviceaccount:app-cjc:p2s-vol`|
  |`sl`|`system:serviceaccount:app-cjc:sl`|
- Ref: [2. Define the application as a Conjur host in policy + 3.Grant access to secrets](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client-authjwt.htm#Setuptheapplicationtoretrievesecrets)
- The demo applications are granted access to the demo database secrets `jtan/db_cityapp` by adding them to `consumers` group

Download the example file and load to the `data` branch:

```console
curl -sLO https://github.com/joetanx/cjc-k8s/raw/main/policies/k8s-hosts.yaml
conjur policy load -b data -f k8s-hosts.yaml
```

### 3.3. JWT authenticator policy

`authn-jwt-k8s.yaml` defines the JWT authenticator endpoint `jtan-k8s`:

- Ref: [Configure the JWT Authenticator](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/authn-jwt/k8s` policy with the necessary variables
- Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice
- The demo applications defined in `k8s-hosts.yaml` are granted access to the JWT Authenticator `authn-jwt/jtan-k8s` by adding them to `consumers` group

Download the example file and load to the `conjur/authn-jwt` branch:

```console
curl -sLO https://github.com/joetanx/cjc-k8s/raw/main/policies/authn-jwt-k8s.yaml
conjur policy load -b conjur/authn-jwt -f authn-jwt-k8s.yaml
```

### 3.4. Populate the variables required by the JWT Authenticator

Ref: [2. Populate the policy variables](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)

```console
PUBLIC_KEYS="$(kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri'))"
ISSUER="$(kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer')"
conjur variable set -i conjur/authn-jwt/jtan-k8s/public-keys -v "{\"type\":\"jwks\", \"value\":$PUBLIC_KEYS}"
conjur variable set -i conjur/authn-jwt/jtan-k8s/issuer -v $ISSUER
conjur variable set -i conjur/authn-jwt/jtan-k8s/token-app-property -v sub
conjur variable set -i conjur/authn-jwt/jtan-k8s/identity-path -v data/jtan/k8s
conjur variable set -i conjur/authn-jwt/jtan-k8s/audience -v vxlab
```

### 3.5. Enable the JWT Authenticator

Ref: [3. Enable the JWT Authenticator](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)

```console
conjur authenticator enable --id authn-jwt/jtan-k8s
```

Verify authenticator status:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/7fc6e675-c6f2-4faa-8501-0499d54246af)

## 4. Preparing Kubernetes configurations

The Conjur Cloud information is passed to the application pods using ConfigMap

Refs: [Prepare the Kubernetes cluster and Golden ConfigMap](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-set-up-apps.htm#PreparetheKubernetesclusterandGoldenConfigMap)

### 4.1. Create namespaces

```console
kubectl create namespace app-hc
kubectl create namespace app-cjc
```

### 4.2. Prepare the necessary values as environments variables to be loaded into ConfigMaps:

```console
CA_CERT="$(openssl s_client -connect apj-secrets.secretsmgr.cyberark.cloud:443 -showcerts </dev/null 2> /dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print $0}')"
CONJUR_CLOUD_URL=https://apj-secrets.secretsmgr.cyberark.cloud/api
CONJUR_ACCOUNT=conjur
CONJUR_AUTHN_URL=$CONJUR_CLOUD_URL/authn-jwt/jtan-k8s
```

### 4.3. Create ConfigMap `apps-cm` for applications

```console
kubectl -n cityapp create configmap apps-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_CLOUD_URL \
--from-literal CONJUR_AUTHN_URL=$CONJUR_AUTHN_URL \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

## 5. Deploy the cityapp test application

### 5.1. Preparing for cityapp deployment

The cityapp application is used to demostrate the various scenarios: hard-coded, secrets-provider, and secretless methods to consume the secrets

The deployment manifest files in this repo is configured use `docker.io/joetanx/cityapp:php`

<details><summary><b>OPTIONAL:</b> Building the cityapp image from source</summary>

To build the container image from [source](https://github.com/joetanx/cityapp-php)

```console
curl -sLO https://github.com/joetanx/cityapp-php/raw/main/Dockerfile
curl -sLO https://github.com/joetanx/cityapp-php/raw/main/index.php
podman build -t cityapp:php .
rm -rf Dockerfile index.php
```

> [!Note]
> Update the manifest files to change `docker.io/joetanx/cityapp:php` to `localhost/cityapp:php` if you built the container image locally

</details>

### 5.2. Deploy cityapp-hardcode

> [!Note]
> 
> The provided manifest exposes the deployment through [NGINX ingress controller](https://github.com/kubernetes/ingress-nginx/) with certificate signed by [cert-manager](https://cert-manager.io/) at host `hc.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/conjur-k8s/raw/main/manifests/hc.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working
- The cityapp connects to the MySQL world database to display random city information
- The database, username and password information is displayed for debugging, and the application is using the credentials hardcoded in the pod environment variables

![image](https://github.com/joetanx/conjur-k8s/assets/90442032/0a98937d-4aed-4dde-af55-f77b77a3ae42)

Rotate the password on the MySQL server and update the new password in Conjur:

|Task|Command|
|---|---|
|Generate random string|`NEWPASS=$(openssl rand -base64 12)`|
|MySQL Server|`mysql -u root -e "ALTER USER 'cityapp'@'%' IDENTIFIED BY '$NEWPASS';"`|
|Conjur|`conjur variable set -i db_cityapp/password -v $NEWPASS`|

Refresh the cityapp-hardcode page: the page will throw an authentication error, since the hard-coded credentials are no longer valid:

```console
SQLSTATE[HY000] [1045] Access denied for user 'cityapp'@'10.244.0.6' (using password: YES)
```

## 6. Retrieving secrets from Conjur with [secrets provider for k8s](https://github.com/cyberark/secrets-provider-for-k8s)

### 6.1. Push to file (p2f)

Ref: [Secrets Provider - Push-to-File mode](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic-p2f.htm)

![p2f](https://github.com/joetanx/conjur-k8s/assets/90442032/6a8c564b-5e5f-43c6-9b1c-15d7585d43a5)

> [!Note]
> 
> The provided manifest exposes the deployment through [NGINX ingress controller](https://github.com/kubernetes/ingress-nginx/) with certificate signed by [cert-manager](https://cert-manager.io/) at host `p2f.cjc.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/cjc-k8s/raw/main/manifests/p2f.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n app-cjc get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/1694aa5d-ea6f-495b-9ffe-63ff2a5f3db4)

### 6.2. Push to Kubernetes secrets (p2s)

Ref [Secrets Provider - Kubernetes Secrets mode](https://docs.cyberark.com/ConjurCloud/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic.htm)

#### 6.2.1. Environment variables mode

![p2s-env](https://github.com/joetanx/conjur-k8s/assets/90442032/8577e1a7-7e1f-416e-8e35-180c7f5b97fb)

> [!Note]
> 
> The provided manifest exposes the deployment through [NGINX ingress controller](https://github.com/kubernetes/ingress-nginx/) with certificate signed by [cert-manager](https://cert-manager.io/) at host `p2s-env.cjc.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/cjc-k8s/raw/main/manifests/p2s-env.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n app-cjc get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/2024df4f-4dae-4da7-94df-fa8e33509bb3)

#### 6.2.2. Volume mount mode

![p2s-vol](https://github.com/joetanx/conjur-k8s/assets/90442032/f26dca90-2b93-4529-bf31-23ce820ec055)

> [!Note]
> 
> The provided manifest exposes the deployment through [NGINX ingress controller](https://github.com/kubernetes/ingress-nginx/) with certificate signed by [cert-manager](https://cert-manager.io/) at host `p2s-vol.cjc.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/cjc-k8s/raw/main/manifests/p2s-vol.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n app-cjc get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/f315f449-c530-426a-bdce-34b9d167052d)

### 6.3. Differences between P2F, P2S-Env and P2S-Vol design patterns

#### 6.3.1. P2F Behaviour

**Secrets provider push destination:** File in volume shared with application

**Application consume secrets from:** File in volume shared with secrets provider

**Rotation behaviour:** File in shared volume gets updated by the secrets provider periodically (in sidecar mode), deployment restart is not required.

#### 6.3.2. P2S-Env Behaviour

**Secrets provider push destination:** Kubernetes secrets

**Application consume secrets from:** Environment variables

**Rotation behaviour:**

Kubernetes secrets get updated by the secrets provider periodically (in sidecar mode).

However, Kubernetes secrets are only pushed to the pods environment during pods start-up, the rotated secret is not updated in the pod's environment variables.

Hence, deployment restart is required to get updated secrets

#### 6.3.3. P2S-Vol Behaviour

**Secrets provider push destination:** Kubernetes secrets

**Application consume secrets from:** Files in volume mount

**Rotation behaviour:**

Kubernetes secrets get updated by the secrets provider periodically (in sidecar mode).

However, updates to the files in the volume mount is dependent on the Kubernetes cluster:
- The kubelet keeps a cache of the current keys and values for the Secrets that are used in volumes for pods on that node.
- Updates to Secrets can be either propagated by an API watch mechanism (the default), based on a cache with a defined time-to-live, or polled from the cluster API server on each kubelet synchronisation loop.
- As a result, the total delay from the moment when the Secret is updated to the moment when new keys are projected to the Pod can be as long as the kubelet sync period + cache propagation delay, where the cache propagation delay depends on the chosen cache type (following the same order listed in the previous paragraph, these are: watch propagation delay, the configured cache TTL, or zero for direct polling).
- Ref: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod

<details><summary><h2>7. ARCHIVED: Deploy cityapp-secretless</h2></summary>

### 7.1. Avoiding secrets from ever touching your application - Secretless Broker

The [Secretless Broker](https://docs.cyberark.com/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm) enables applications to connect securely to services without ever having to fetch secrets

In the provided [`sl.yaml`](./manifests/sl.yaml) manifest, the `secretless broker` runs as a sidecar container alongside with the `cityapp` container

The Secretless Broker will:
- Authenticate to Conjur
- Retreive the secrets
- Connect to the database
- Enable a database listener for the application to connect to

Application connection flow with Secretless Broker:

![sl](https://github.com/joetanx/conjur-k8s/assets/90442032/dadde68b-b6d7-429a-a14e-c31489f6924e)

### 7.2. Prepare the ConfigMap to be used by Secretless Broker

Secretless Broker needs some configuration to determine where to listen for new connection requests, where to route those connections, and where to get the credentials for each connection

- Ref: [Prepare the Secretless configuration](https://docs.cyberark.com/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm#PreparetheSecretlessconfiguration)

We will map the `sl-cm.yaml` to the `cityapp` container using a ConfigMap

☝️ Secretless Broker also need to locate Conjur to authenticate and retrieve credentials, this was done in the [previous step](#44-create-configmap-apps-cm-for-applications) where we loaded the `apps-cm` ConfigMap

```console
curl -sLO https://github.com/joetanx/cjc-k8s/raw/main/manifests/sl-cm.yaml
kubectl -n app-cje create configmap sl-cm --from-file=sl-cm.yaml && rm -f sl-cm.yaml
```

### 7.3. Deploy the Secretless-based cityapp

> [!Note]
> 
> The provided manifest exposes the deployment through [NGINX ingress controller](https://github.com/kubernetes/ingress-nginx/) with certificate signed by [cert-manager](https://cert-manager.io/) at host `sl.cjc.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/cjc-k8s/raw/main/manifests/sl.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n app-cjc get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list that the application is connecting to `127.0.0.1` using empty credentials

![image](https://github.com/joetanx/conjur-k8s/assets/90442032/7ff29a0f-f7da-4cb0-8abb-9dec1c8e55a5)

</details>

## 8. Viewing audit events

[Activities](https://docs.cyberark.com/Product-Doc/OnlineHelp/ConjurCloud/Latest/en/Content/Audit/isp_system-activities.htm) in Conjur Cloud can be viewed on CyberArk Audit where details of the action (e.g. authenicate, fetch) and the host identities are recorded

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/48901eba-34d1-45a4-ba11-a3aaade458f6)
