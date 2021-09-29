# Sentinel Extensibility + Hunting

- Topics
  - TODO KQL UNIONs
  - TODO Create bookmarks...

## Exercise 1: Execute Attack

You will execute an attack on your paw virtual machine that will do some not so great things. Since your environment has Azure Sentinel configured with all the various data connectors, you should get a basic alert fired. It will be your job to determine what the attack did.

### Task 0: Setup

1. Open **OneDrive**
2. Login as your lab credentials, open the OneDrive folder, ensure that you see the following files:

    ![OneDrive initialize.](./media/one-drive-init.png "OneDrive initialize")

### Task 1: Execute Attack

1. Switch to your **wssecuritySUFFIX-paw-1** virtual machine
2. Open a PowerShell window, run the following, please do not look at the script (it won't help you much anyway):

    ```PowerShell
    `.\artifacts\day-02\Attack_windows.ps1`
    ```

    > **Note** This script will execute some commands that were the result of a hacker gaining access to the credentials of an administrator.  It is up to you to determine how they did it through the next series of exercises.

## Exercise 2: Investigating Incidents and Alerts

The previous exercise created a breach in a system in your environment. You will need to determine what happened and determine what remediation can be done (if any).

### Task 1: Review Alerts

1. Open Azure Security Center
2. Under **General**, select **Security alerts**
3. Select the alert called **Potential attempt to bypass AppLocker detected**

    ![Azure Security Center alerts.](./media/azure_security_center_alerts.png "Select the first alert")

4. Select **View full details**

    ![Review an alert.](./media/azure_security_center_alert1.png "Review an alert")

5. Review the alert details

    ![Review an alert.](./media/azure_security_center_alert1_details.png "Review an alert")

6. Can you answer the following questions?
   1. What host did the alert come from?
   2. Who is the user related?
   3. What kind of attack do you think it is?
   4. Where did it come from?

### Task 2: Go Hunting

1. Open Azure Sentinel
2. Under Threat Management, select **Hunting**
3. Select **Run all queries**

    ![Run all the hunting queries.](./media/azure_sentinel_hunting.png "Run all the hunting queries")

### Task 3: Explore Hunting queries

1. Sort by results or results delta, review any items that look suspicious
2. Select the **Port opened for an Azure Resource** query

    ![Hunting query.](./media/azure_sentinel_hunting_results.png "Hunting query")

3. Select **Run query**, then select **View Results**.  

    ![Run hunting query.](./media/azure_sentinel_hunting_run_query.png "Run hunting query")

4. Does this give you any clues or is it a dead end?

### Task 4: Review Incidents

1. Open Azure Sentinel
2. Under Threat Management, select **Incidents**
3. Answer the following questions:

   - Do you see any new incidents?
   - Did you expect to see something that you are not seeing?  If so, how might you make it surface?

4. Review the Incidents, find any that were recently created (as of when you ran the above attack script)

5. For each incident, select it and then assign yourself (the lab account)

### Task 5: Review Investigation Graphs

1. For each incident, select it, then select **Investigate**, this will display the investigation graph

    > **Note** You'll only be able to investigate the incident if you used the entity mapping fields when you set up your analytics rule. The investigation graph requires that your original incident includes entities. Azure Sentinel currently supports investigation of incidents up to 30 days old.

2. Review the items that are displayed

3. Hover over each entity type, then review the options available to you for that entity type

    > **Note** Each entity will reveal a list of questions designed by security experts and analysts to deepen your investigation. These are called exploration queries.

4. Select **Related alerts**, notice any other items are added to the graph

### Task 5: Review Alert Timelines

1. Select the **Timeline** toggle on the right, you should now see the series of alerts and the order in which they were fired

### Task 6: Troubleshoot with KQL

1. What kind of queries do you think you should run to get more details?
2. Try running the following to look for entity related items, under **General**, select **Logs**
3. Run the following KQL to find all entries related to a user:

    ```KQL
    SigninLogs
    | where Account in ('')
    | where ResultType == "0"

    OfficeActivity
    | where Account in ('')
    | where ResultType == "0"
    ```

4. Run the following KQL to find all entries related to a device:

    ```KQL
    search Computer !in ("-")
    | summarize AggregatedValue = count() by Computer
    | where Computer != ""
    | extend ComputerName = toupper(split (Computer, ".",0))
    ```

5. Run the following KQL to find all entries related to an IP address:

    ```KQL
    SigninLogs
    | where IPAddress in ('')
    | where ResultType == "0"

    OfficeActivity
    | where IPAddress in ('')
    | where ResultType == "0"
    ```

### Task 7: Answer the Questions

1. Who caused the attack to occur?
2. What entities were involved?
3. What were the steps of the attack?

### Task 8: Close the Incidents

1. For each incident, select it, then select the appropriate status (`closed`) with a classification (`true positive`).
2. For the comment, type `User error in judgement`.
3. Select **Apply**

## Exercise 3 : Use STIX and TAXII with Azure Sentinel

As part of your investigation, you found out someone else had already discovered this attack pattern and published it to a TAXII feed. You want to bring these alerts into your Azure Sentinel for future incident creation.

### Task 1: Create TAXII Connections

1. Open the Azure Portal in your **wssecuritySUFFIX-paw-1** virtual machine
2. Select **Azure Sentinel**
3. Select the log analytics workspace
4. Under **Configuration**, select **Data Connectors**
5. Select **Threat Intelligence – TAXII** from the list of the data connectors

    ![TAXII Connector.](./media/sentinel_data_connector_taxii.png "TAXII Connector.")

6. Click the **Open Connector page** button.
7. For the **Friendly name**, type **Mitre**
8. Enter the API Root, type **https://cti-taxii.mitre.org/stix**
9. For Collection ID, type **95ecc380-afe9-11e4-9b6c-751b66dd541e**
10. For username and password leave blank
11. Click the **Add** button.

    ![Mitre Taxii.](./media/sentinel_data_connector_taxii_config.png "Mitre Taxii")

12. For the **Friendly name**, type **Anomali**
13. Enter the API Root, type **https://limo.anomali.com/api/v1/taxii2/feeds/**
14. For Collection ID, type **107**
15. For username and password, type **guest**
16. Click the **Add** button.

    > **Note** If you get an error, make sure you entered guest for the username and password.

17. You should now see a confirmation on the notification dialog that the connection was established successfully. The TAXII Server will now show up in the List of the configured TAXII Servers.

    ![Taxii connections.](./media/sentinel_data_connector_taxii_config2.png "Taxii connections")

### Task 2: Create alerts

1. Under **General**, select **Logs**
2. You should now see an **Azure Sentinel** table category displayed
3. Expand it and then expand **ThreatIntelligenceIndicator**. You should now see a list of all the alerts that were imported from the TAXII connectors

    ![Taxii data.](./media/sentinel_data_connector_taxii_data.png "Taxii data")

4. Under **Threat Management**, select **Threat Intelligence**
5. You should notice several new items displayed based on type and the source (you should see Anomali and Mitre as sources)

    ![Taxii data anomali.](./media/sentinel_data_connector_ti_anomali.png "Taxii data anomali")

6. Select one of the items
7. In the dialog on the right, click the **0 Alerts** area. You will be directed to Log Analytics with the query that represents the item
8. Select **New alert rule->Create Azure Sentinel alert**, follow the dialogs as you have done before in previous labs.
9. Congrats, you have imported external security provider data and created an alert from it using the STIX and TAXII standards.

## Exercise 4 : SOC Efficiency

You would like to measure your SOC efficiency, specifically around Incident response.

### Task 1: Security Operations Efficiency Workbook

1. Under **Threat Management**, select **Workbooks**
2. Search for the **Security operations efficiency** workbook

    ![SOC Efficiency workbook.](./media/sentinel_workbook_soc_efficiency.png "SOC Efficiency workbook")

3. In the dialog, scroll to the bottom, select **Save**
4. Select the region, then select **OK**
5. Select **View template**
6. Select **Auto refresh:Off**, then select **10 minutes**
7. Select **Apply**, you should now see metrics based on your Azure Sentinel incidents
