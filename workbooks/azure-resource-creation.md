# Azure Resource Creation – Geo Enrichment Workbook

This workbook uses **Microsoft Sentinel / Log Analytics** to map where **Azure resource creation** is occurring worldwide. It filters successful *WRITE* operations from **AzureActivity**, enriches caller IPs with a GeoIP watchlist, and plots the results on a map so you can quickly spot high-volume creators, unusual regions, and potential misuse.

![Azure Resource Creation Map](https://raw.githubusercontent.com/arthurjoseph17/arthurjoseph17/main/images/azure-resource-creation-1.png)  


---

## 📖 Description

- **Signal:** `AzureActivity` (control plane)  
- **Scope:** Successful `*WRITE` operations only (i.e., resource creations/updates)  
- **Who:** Human identities only (filters out GUID-style callers like service principals)  
- **Where:** IPv4 callers with geolocation enrichment from a **GeoIP watchlist**  
- **Window:** Last 30 days (adjust in the workbook time picker)

---

## 🔎 KQL Query

> **Prereqs**
> - A **watchlist** named `geoip` containing IPv4 network ranges and geo columns (e.g., `network`, `latitude`, `longitude`, `countryname`, `cityname`).
> - Uses `ipv4_lookup()` to join `CallerIpAddress` to the watchlist.

### Query
```kql
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords =
    AzureActivity
    // Exclude GUID-like callers (service principals, app IDs)
    | where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
    // Require IPv4 caller IP
    | where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    // Successful resource writes
    | where OperationNameValue endswith "WRITE"
      and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
    // Count creations by caller/IP
    | summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project
    Caller,
    CallerPrefix = split(Caller, "@")[0],
    CallerIpAddress,
    ResouceCreationCount,
    Country = countryname,
    Latitude = latitude,
    Longitude = longitude,
    friendly_label = strcat(CallerPrefix, " - ", cityname, ", ", countryname)
```
🌍 Visualization

Type: Map (Lat/Long)

Location fields: Latitude, Longitude

Bubble size: ResouceCreationCount (Sum)

Bubble color: Heatmap by ResouceCreationCount (greenRed palette)

Label: friendly_label (<alias> - <city>, <country>)

📷 Screenshots

![Azure Resource Creation JSON Config](https://raw.githubusercontent.com/arthurjoseph17/arthurjoseph17/main/images/azure-resource-creation-2.png)

⚡ Use Cases

Spot unusual geographies for resource creation (possible risky access or misconfig).

Identify top creators (individuals or jump boxes) by IP and volume.

Triage suspicious spikes in creation activity after off-hours changes.

Correlate with Change Management or Deployment windows for validation.

🧩 Tips

If you primarily use service principals, remove the GUID filter to include them and group by Caller or Claims.

Add extra filters (e.g., ResourceGroup, SubscriptionId, Category) for scoped views.

Swap the watchlist for an official IP-to-Geo table if you have one available in your environment.

Extend with country allow/deny lists to flag out-of-policy regions
