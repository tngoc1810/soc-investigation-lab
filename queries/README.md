# Query pack and validation boundary

SQLite queries are executed against this project's database using python -m soclab query NAME --db PATH. They are read-only and tested against fixture/public-case results. They are useful analyst pivots, not a live SIEM deployment.

Sentinel KQL references the official [WindowsEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent). It assumes native field names and a configured Windows event collector. Historical replay ranges are explicit; a last-hour filter would hide these historical samples. These queries have not been executed in an Azure workspace. auth_burst.kql uses fixed bins, so it is not equivalent to the engine's sliding window/cooldown.

The Splunk example assumes index=soc_lab, sourcetype=soclab:json and JSON extraction compatible with the interchange schema. Configure event timestamps from timestamp when ingesting historical records; otherwise searches can use ingestion time. This query has not been executed on a Splunk instance.

Three Sigma rules were parsed with pySigma 1.5.1, including condition references. They map equivalent single-event hypotheses to Sigma log sources. Parser success is not proof of backend field mappings, conversion equivalence or actual alerting. The project's custom JSON rules remain the executable core; the Sigma files are separate portable references.

This distinction matters in a portfolio: it demonstrates rule portability and schema reasoning while making the missing live-SIEM validation visible.
