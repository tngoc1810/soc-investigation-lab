SELECT timestamp, host, record_id, event_uid,
       json_extract(event_data, '$.Image') AS image,
       json_extract(event_data, '$.CommandLine') AS command_line
FROM events
WHERE lower(provider) = 'microsoft-windows-sysmon'
  AND lower(channel) = 'microsoft-windows-sysmon/operational'
  AND event_id = 1
  AND lower(json_extract(event_data, '$.Image')) LIKE '%\mshta.exe'
  AND (instr(lower(json_extract(event_data, '$.CommandLine')), 'http://') > 0
       OR instr(lower(json_extract(event_data, '$.CommandLine')), 'https://') > 0)
ORDER BY timestamp, source_line;
