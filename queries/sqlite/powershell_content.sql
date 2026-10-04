SELECT timestamp, host, event_id, record_id, event_uid,
       json_extract(event_data, '$.ScriptBlockText') AS script_block,
       json_extract(event_data, '$.ContextInfo') AS context,
       json_extract(event_data, '$.Payload') AS payload
FROM events
WHERE lower(provider) = 'microsoft-windows-powershell'
  AND lower(channel) = 'microsoft-windows-powershell/operational'
  AND event_id IN (4103, 4104)
ORDER BY timestamp, source_line;
