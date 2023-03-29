### OCI IAM CleanUp disabled Users from Oracle SaaS Fusion Connector

This little utility is designed to be called periodically in order to delete disabled users in OCI IAM (IDCS) from Oracle SaaS Fusion Connector (HCM, ERP, etc..) as "Authoritative Sync" in OCI IAM. It is written as a serverless function using the [fn framework](https://fnproject.io/) to run in [OCI](https://cloud.oracle.com/). 

Uses:

* ClientID/ClientSecret authentication with OCI IAM (IDCS)
* Secrets in Vault to store the ClientSecret for the above
* Resource principal Authentication for OCI API invocations (Secrets, Logging)
* Send to OCI Logging the users deletet for trace activities

Required configuration:

* Client in IDCS (with User Administrator, and ClientSecret associated with it for Client Credentials)
* Private key for the above stored in Secrets
* LogGroup and Logs created in OCI Logging
* Dynamic Group which includes the running function
* Policies on the Dyanmic Group for read access to the Secret, and put logs in OCI Loggings
* Some sort of scheduler (I used OCI Alarm and Notification)


Navigating this repo:

Structure is a little monolithic... Main implementation is in func.py. Reusable OCI IAM APIs are in IAMClient.py. 
Perpetual TODO: Better test coverage...
