## Integrate Kubernetes with Conjur Cloud

Overview:
- Construct the JWT authenticator for Kubernetes
- Deploy demonstration application `cityapp` in different modes: hard-code, secrets provider and secretless

### Software Versions

- RHEL 9.2
- Kubernetes 1.27

### Servers

| Hostname  | Role |
| --- | --- |
| mysql.vx  | MySQL server  |
| kube.vx  | Single-node Kubernetes cluster  |

## 1. Setup

### 1.1. Kubernetes cluster

- This demo should work with any flavour of Kubernetes clusters (On-prem, AKS, EKS), but was tested with a single-node on-prem Kubernetes cluster in my lab
- For a guide to setup a single-node on-prem Kubernetes cluster: <https://github.com/joetanx/setup/blob/main/cri-o-kube.md>

### 1.2. Setup MySQL database

- Setup MySQL database according to this guide: <https://github.com/joetanx/setup/blob/main/mysql.md>

### 1.3. Login to Conjur Cloud

> **Note** This can be performed on any machine (including Windows and macOS)
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

## 2. Prepare Conjur policies

☝️ Policies on Conjur Cloud are segregated into `data` and `conjur` branches:

- `data` are meant for resources (e.g. hosts, groups, variables)
  - The sub-policy `data/vault` contains secrets synchronized from Privilege Cloud
- `conjur` holds the authencator services

Ref: https://docs-er.cyberark.com/ConjurCloud/en/Content/ConjurCloud/cl_policytree.htm

> **Note** The policy examples provided in this repository uses a `jtan` prefix
> 
> Edit the prefix to your desired name before loading them

### 2.1. Secrets policy

`app-vars.yaml` contains 3 sub-policies:

- `jtan/db_cityapp`: MySQL database credential used in this Kubernetes integration
- `jtan/db_cicd`: MySQL database credential used for future CI/CD integration demo (e.g. GitLab, Jenkins)
- `jtan/aws_api`: AWS Secret Access Keys used for future CI/CD integration demo (e.g. GitLab, Jenkins)

Download the example file and load to the `data` branch:

```console
conjur policy load -f app-vars.yaml -b data
```

Populate the database credentials for this Kubernetes integration

```console
conjur variable set -i data/jtan/db_cityapp/address -v mysql.vx
conjur variable set -i data/jtan/db_cityapp/username -v cityapp
conjur variable set -i data/jtan/db_cityapp/password -v Cyberark1
```

### 2.2. Host identity policy

`k8s-hosts.yaml` defines `jtan/k8s` policy with:

- Demo applications `cityapp-secretsprovider` and `cityapp-secretless` identified by `system:serviceaccount:cityapp:cityapp-secretsprovider` and `system:serviceaccount:cityapp:cityapp-secretless`
  - Ref: [2. Define the application as a Conjur host in policy + 3.Grant access to secrets](https://docs-er.cyberark.com/ConjurCloud/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client-authjwt.htm#Setuptheapplicationtoretrievesecrets)
- The demo applications are granted access to the demo database secrets `jtan/db_cityapp` by adding them to `consumers` group

Download the example file and load to the `data` branch:

```console
conjur policy load -f k8s-hosts.yaml -b data
```

### 2.3. JWT authenticator policy

`authn-jwt-k8s.yaml` defines the JWT authenticator endpoint `jtan-k8s`:

- Ref: [Configure the JWT Authenticator](https://docs-er.cyberark.com/ConjurCloud/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/authn-jwt/k8s` policy with the necessary variables
- Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice
- The demo applications defined in `k8s-hosts.yaml` are granted access to the JWT Authenticator `authn-jwt/jtan-k8s` by adding them to `consumers` group

Download the example file and load to the `conjur/authn-jwt` branch:

```console
conjur policy load -f authn-jwt-k8s.yaml -b conjur/authn-jwt
```

### 2.4. Populate the variables required by the JWT Authenticator

Ref: [2. Populate the policy variables](https://docs-er.cyberark.com/ConjurCloud/en/Content/Operations/Services/cjr-authn-jwt-cloud.htm#ConfiguretheJWTAuthenticator)

```console
PUBLIC_KEYS="$(kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri'))"
ISSUER="$(kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer')"
conjur variable set -i conjur/authn-jwt/jtan-k8s/public-keys -v "{\"type\":\"jwks\", \"value\":$PUBLIC_KEYS}"
conjur variable set -i conjur/authn-jwt/jtan-k8s/issuer -v $ISSUER
conjur variable set -i conjur/authn-jwt/jtan-k8s/token-app-property -v sub
conjur variable set -i conjur/authn-jwt/jtan-k8s/identity-path -v data/jtan/k8s
conjur variable set -i conjur/authn-jwt/jtan-k8s/audience -v vxlab
```

### 2.5. Enable the JWT Authenticator

Ref: [3. Enable the JWT Authenticator](https://docs-er.cyberark.com/ConjurCloud/en/Content/Operations/Services/cjr-authn-jwt-cloud.htm#ConfiguretheJWTAuthenticator)

```console
conjur authenticator enable --id authn-jwt/jtan-k8s
```

Verify authenticator status:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/7fc6e675-c6f2-4faa-8501-0499d54246af)

## 3. Prepare Kubernetes cluster

The Conjur Cloud information is passed to the application pods using ConfigMap

Refs:
- https://docs-er.cyberark.com/ConjurCloud/en/Content/Integrations/k8s-ocp/k8s-jwt-set-up-apps.htm
- https://docs-er.cyberark.com/ConjurCloud/en/Content/Integrations/k8s-ocp/cjr-k8s-secrets-provider-ref.htm

1. Create the `cityapp` namespace: `kubectl create namespace cityapp`

2. Prepare the necessary values as environments variables to be loaded into ConfigMap:

```console
CA_CERT="$(openssl s_client -connect apj-secrets.secretsmgr.cyberark.cloud:443 -showcerts </dev/null 2> /dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print $0}')"
CONJUR_CLOUD_URL=https://apj-secrets.secretsmgr.cyberark.cloud/api
AUTHENTICATOR_ID=jtan-k8s
CONJUR_ACCOUNT=conjur
CONJUR_AUTHN_URL=$CONJUR_CLOUD_URL/authn-jwt/jtan-k8s
```

3. Create ConfigMap `apps-cm` for applications:

```console
kubectl -n cityapp create configmap apps-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_CLOUD_URL \
--from-literal CONJUR_AUTHN_URL=$CONJUR_AUTHN_URL \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

## 4. Preparing for cityapp deployment

The cityapp application is used to demostrate the various scenarios: hard-coded, secrets-provider, and secretless methods to consume the secrets

The deployment manifest files in this repo is configured use `docker.io/joetanx/cityapp:php`

### 4.1. Optional - build cityapp container image

To build the container image from [source](https://github.com/joetanx/cityapp-php)

```console
curl -O https://raw.githubusercontent.com/joetanx/cityapp-php/main/Dockerfile
curl -O https://raw.githubusercontent.com/joetanx/cityapp-php/main/index.php
podman build -t cityapp:php .
rm -rf Dockerfile index.php
```

## 5. Deploy cityapp-hardcode

> **Note** The provided manifest exposes the deployment through NGINX ingress controller at host `hardcode.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl -n cityapp apply -f https://raw.githubusercontent.com/joetanx/conjur-k8s/main/cityapp-hardcode.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working
- The cityapp connects to the MySQL world database to display random city information
- The database, username and password information is displayed for debugging, and the application is using the credentials hardcoded in the pod environment variables

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/b904b20d-2116-483f-a2e8-9500fc621d76)

Rotate the password on the MySQL server and update the new password in Conjur:

| Target | Command |
| --- | --- |
| MySQL Server | `mysql -u root -e "ALTER USER 'cityapp'@'%' IDENTIFIED BY 'qBIs3urqM0aG';"` |
| Conjur | `conjur variable set -i data/jtan/db_cityapp/password -v qBIs3urqM0aG` |

Refresh the cityapp-hardcode page: the page will throw an authentication error, since the hard-coded credentials are no longer valid:

```console
SQLSTATE[HY000] [1045] Access denied for user 'cityapp'@'10.244.0.6' (using password: YES)
```

## 6. Retrieving credentials using Secrets Provider for Kubernetes

Ref: [Secrets Provider - Push-to-File mode](https://docs-er.cyberark.com/ConjurCloud/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic-p2f.htm)

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/cba5a8ab-3131-4e76-8947-95a40f0fc5db)

> **Note** The provided manifest exposes the deployment through NGINX ingress controller at host `secretsprovider.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
curl -sO https://raw.githubusercontent.com/joetanx/cjc-k8s/main/cityapp-secretsprovider.yaml
kubectl -n cityapp apply -f cityapp-secretsprovider.yaml && rm -f cityapp-secretsprovider.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/310bb336-ad2a-4a21-98f9-9097f4b80525)

## 7. Deploy cityapp-secretless

### 7.1. Avoiding secrets from ever touching your application - Secretless Broker

The [Secretless Broker](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm) enables applications to connect securely to services without ever having to fetch secrets

In this demo, `secretless broker` will run as a sidecar container alongside with the `cityapp` container

The Secretless Broker will:
- Authenticate to Conjur
- Retreive the secrets
- Connect to the database
- Enable a database listener for the application to connect to

Application connection flow with Secretless Broker:

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/94f798ea-b6d9-4eb8-b6f0-9fda0ee8ae54)

### 7.2. Prepare the ConfigMap to be used by Secretless Broker

Secretless Broker needs some configuration to determine where to listen for new connection requests, where to route those connections, and where to get the credentials for each connection

- Ref: [Prepare the Secretless configuration](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm#PreparetheSecretlessconfiguration)

We will map the `cityapp-secretless-cm.yaml` to the `cityapp` container using a ConfigMap

☝️ Secretless Broker also need to locate Conjur to authenticate and retrieve credentials, this was done in the previous step where we loaded the `apps-cm` ConfigMap

```console
curl -sO https://raw.githubusercontent.com/joetanx/cjc-k8s/main/secretless-cm.yaml
kubectl -n cityapp create configmap secretless-cm --from-file=secretless-cm.yaml && rm -f secretless-cm.yaml
```

### 7.3. Deploy the Secretless-based cityapp

> **Note** The provided manifest exposes the deployment through NGINX ingress controller at host `secretsprovider.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
curl -sO https://raw.githubusercontent.com/joetanx/cjc-k8s/main/cityapp-secretless.yaml
kubectl -n cityapp apply -f cityapp-secretless.yaml && rm -f cityapp-secretless.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list that the application is connecting to `127.0.0.1` using empty credentials

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/d6c7b540-b853-4837-9d89-114e2bd0f7a0)

## 8. Viewing audit events

[Activities](https://docs-er.cyberark.com/ConjurCloud/en/Content/Audit/isp_system-activities.htm) in Conjur Cloud can be viewed on CyberArk Audit where details of the action (e.g. authenicate, fetch) and the host identities are recorded

![image](https://github.com/joetanx/cjc-k8s/assets/90442032/48901eba-34d1-45a4-ba11-a3aaade458f6)
