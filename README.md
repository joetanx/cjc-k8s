## Login to Conjur Cloud

```console
[root@foxtrot ~]# conjur init
Enter the URL of your Conjur Cloud (use the following format: https://<subdomain>.secretsmgr.cyberark.cloud/api): https://apj-secrets.secretsmgr.cyberark.cloud/api
Configuration written to /root/.conjurrc

Successfully initialized the Conjur Cloud CLI
To start using the Conjur Cloud CLI, log in to the Conjur Cloud by running `conjur login`
[root@foxtrot ~]# cat .conjurrc
---
cert_file: ''
conjur_account: conjur
conjur_url: https://apj-secrets.secretsmgr.cyberark.cloud/api
identity_url: https://aap4062.id.cyberark.cloud
[root@foxtrot ~]# conjur login
Enter your username: joe.tan@cyberark.cloud.3434
Enter your password or API key (this will not be echoed):
Choose your secondary authentication method:
(1) Send email with a one-time code to xxxx@cyberark.com
(2) Send text with a one-time code to XXX-5097
Type your selection: 1
A one-time code has been sent to the method of your choice. Enter the one-time code that you received:
86990157
WARNING: No supported keystore found! Saving Conjur Cloud token in '/root/.conjur_credentials'. Make sure to logoff after you have finished using the CLI
Successfully logged in to Conjur Cloud
[root@foxtrot ~]# cat .conjur_credentials
{"machine": "https://apj-secrets.secretsmgr.cyberark.cloud/api", "username": "joe.tan@cyberark.cloud.3434", "password": null, "api_key": null, "api_token": "{\"protected\":\"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiJkZDkzZjhkNjNmYjE4OGZhMWMxYjllOWU1ZDJiMzFjYWFjNDkwZmY5ODBhNDhjNzI0OTdmYzhjMzI2MjJhNTUyIn0=\",\"payload\":\"eyJzdWIiOiJqb2UudGFuQGN5YmVyYXJrLmNsb3VkLjM0MzQiLCJleHAiOjE2ODQ4NTEwNjUsImlhdCI6MTY4NDg0NzQ2NX0=\",\"signature\":\"ncNTktNwrHRoYUF7HlOTnMjCjsuaU1kPyYAvrt41_VPm7I1hsmHZTKieVEUvoUYEFDlQCjmmOiCRoinfJfF4HwzkEVNkJQNtmHref8dbQzJiT_tz2poGMoGs0S-Zp1zT0caSHl6KkdEQhXKL6C-hlYqPCz7j-MRjNaSPI66Hjp9QV_TQW2vkvZdBydj5uj6qcOEmHA8uusLcfpvXpaOhjSm9ZkFmV_mH8jjgTzyyXLbQC7DDX5HRo0CiylJYc4yYwiePsP9ajLnAtw1oB2TmvZ2R2jFpMuvdTNRaFVCJoA-NEBfs6-zXhDwxeVUn3k6jpX6Cx6ay6KELeQwnqdCEjthLkV8-3SAFJgDzJ_efP8Ca1dgiXDmehE_M_5dYoiNV\"}", "api_token_expiration": "2023-05-23 22:08:05"}
```
