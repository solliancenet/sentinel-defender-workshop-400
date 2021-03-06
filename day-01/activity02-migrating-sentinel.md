# Activity 2: Migrate SIEM to Microsoft Sentinel

For compliance reasons, Contoso would like to maintain raw and filtered logs for longer than 90 days, but no longer than 365 days (1 year).  They would like to know how they might be able to accomplish this with Microsoft Sentinel and Azure tools.

**Requirements**

* Determine supported and unsupported connectors.
* Determine the work/effort to migrate.
* Decide if a hybrid approach is appropriate.
* Keep raw and filtered logs for longer than 90 days.
* Remove data after 365 days

**Environment**

* WWI ingests data from their F5 BIG-IP load balancers, Baracuda firewalls, Cisco Meraki, Okta identity, and several Windows and Linux servers.
* This data has a lot of extra fields and content that is not important for their current queries and alerts.
* Currently they use a custom process with LogStash to filter out data they do not need and import it into Splunk.

## Whiteboard

Open your whiteboard for the event, and in the area for Activity 2 provide your answers to the following challenges.

*The following challenges are already present within the whiteboard template provided.*

Challenges

1. Is it possible to filter raw event and log data before it gets to Microsoft Sentinel?
2. How might WWI enrich their data before it gets into Microsoft Sentinel?
3. Are all the current connectors supported in Log Analytics / Microsoft Sentinel?
4. What items will WWI need to migrate from Splunk? Can any of it be automated?
5. If not all connectors are supported, can they run in a SIEM hybrid mode until they are?
