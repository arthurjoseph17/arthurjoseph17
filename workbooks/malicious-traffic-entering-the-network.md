# Malicious Traffic Entering the Network — Workbook

This workbook visualizes **malicious inbound flows** detected by Azure’s flow analytics and maps the **source locations** worldwide. It enriches flow sources with a GeoIP watchlist and projects them on a heat-colored bubble map so you can rapidly triage hotspots, noisy IPs, and suspect regions.

---

## 📖 Description

- **Signal:** `AzureNetworkAnalytics_CL` (NSG flow logs / Traffic Analytics)  
- **Scope:** `FlowType_s == "MaliciousFlow"` (Azure-classified malicious traffic)  
- **Enrichment:** IPv4 → Geo (city/country/lat/long) via a watchlist named **`geoip`**  
- **Window:** Last 30 days (set by the workbook time picker)

> 💡 **Prereqs**
> - NSG Flow Logs v2 + **Traffic Analytics** enabled on the workspace feeding `AzureNetworkAnalytics_CL`.  
> - A watchlist named **`geoip`** with columns such as `network`, `cityname`, `countryname`, `latitude`, `longitude`.

---

## 🔎 KQL Query

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows =
    AzureNetworkAnalytics_CL
    | where FlowType_s == "MaliciousFlow"
    // Optional scoping to a specific internal host:
    // | where SrcIP_s == "10.0.0.5"
    | order by TimeGenerated desc
    | project
        TimeGenerated,
        FlowType = FlowType_s,
        IpAddress = SrcIP_s,
        DestinationIpAddress = DestIP_s,
        DestinationPort = DestPort_d,
        Protocol = L7Protocol_s,
        NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project
    TimeGenerated,
    FlowType,
    IpAddress,
    DestinationIpAddress,
    DestinationPort,
    Protocol,
    NSGRuleMatched,
    latitude,
    longitude,
    city = cityname,
    country = countryname,
    friendly_location = strcat(cityname, " (", countryname, ")")


🌍 Visualization

Type: Map (Lat/Long)

Location fields: latitude, longitude

Bubble size: city (Count)

Bubble color: Heatmap (greenRed) by city count

Label: friendly_location (e.g., Irwin (United States))

📷 Screenshots




⚡ Use Cases

Identify hotspot geographies sending malicious traffic into your environment.

Triage by NSG rules matched and destination ports to prioritize blocks.

Track campaign spikes over time by country/city.

Pivot from a region → source IPs → NSG rule → impacted destination IPs.

🧩 Tips & Extensions

Add filters for DestinationPort (e.g., RDP/3389, SSH/22) to spotlight targeted services.

Join with a threat-intel table to flag known bad source IP ranges.

Layer an allow/deny region list to flag out-of-policy traffic.

If you prefer counts by unique IpAddress instead of city, change the size & legend metrics to IpAddress and aggregation to Count
