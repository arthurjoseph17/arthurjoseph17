# Entra ID (Azure) Authentication Success/Failure Workbook

This workbook leverages **Microsoft Sentinel** and **Log Analytics** to visualize successful and failed Entra ID (Azure AD) authentication attempts across the globe. It allows security teams to track where user sign-ins are occurring, measure authentication volumes, and quickly identify unusual access patterns or potential compromise.

---

## 📖 Description

The workbook queries **SigninLogs** from your Log Analytics workspace and aggregates authentication events. Each authentication is plotted on a world map using latitude and longitude values derived from the `LocationDetails` field. This provides a clear visualization of global login activity, helping identify:

- **Legitimate user access patterns** by geography  
- **Suspicious activity** (e.g., sudden spikes in logins from unexpected regions)  
- **Failed login attempts** that may indicate brute-force or password spray attacks  

The visualization supports both **success (ResultType == 0)** and **failure (ResultType != 0)** queries. Security teams can toggle between these to differentiate authorized access from attempted intrusions.

---

## 🔎 KQL Queries

### ✅ Successful Authentications
```kql
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by 
    Identity, 
    Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), 
    Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), 
    City = tostring(LocationDetails["city"]), 
    Country = tostring(LocationDetails["countryOrRegion"])
| project 
    Identity, 
    Latitude, 
    Longitude, 
    City, 
    Country, 
    LoginCount, 
    friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

❌ Failed Authentications

```
SigninLogs
| where ResultType != 0
| summarize LoginCount = count() by 
    Identity, 
    Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), 
    Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), 
    City = tostring(LocationDetails["city"]), 
    Country = tostring(LocationDetails["countryOrRegion"])
| project 
    Identity, 
    Latitude, 
    Longitude, 
    City, 
    Country, 
    LoginCount, 
    friendly_label = strcat(Identity, " - ", City, ", ", Country)

🌍 Visualization

Visualization Type: Map

Location Information: Latitude and Longitude from LocationDetails

Bubble Size: Based on LoginCount (aggregated sign-ins per identity/location)

Labels: User Identity with City and Country (friendly_label)

Color Coding:

Green: Successful Authentications

Red: Failed Authentications

📷 Screenshots:








⚡ Use Cases

Detecting impossible travel scenarios (e.g., logins from New York and Tokyo within minutes)

Identifying unusual access regions that deviate from standard user behavior

Monitoring failed logins to quickly triage potential brute-force or password spray attacks

Providing executives and security leaders with visual authentication metrics for reporting

📌 Notes

Ensure your Log Analytics workspace has SigninLogs enabled via Azure AD diagnostic settings

Customize the time range (Last 24 hours, Last 7 days, etc.) to refine analysis

This workbook can be cloned and extended to include additional authentication signals, such as MFA prompts or conditional access outcomes
