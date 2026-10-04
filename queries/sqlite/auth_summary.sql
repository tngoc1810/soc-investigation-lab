SELECT host, event_id,
       json_extract(event_data, '$.TargetUserName') AS target_user,
       json_extract(event_data, '$.TargetDomainName') AS target_domain,
       json_extract(event_data, '$.IpAddress') AS source_ip,
       json_extract(event_data, '$.LogonType') AS logon_type,
       json_extract(event_data, '$.SubStatus') AS substatus,
       COUNT(*) AS event_count, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
FROM events
WHERE lower(provider) = 'microsoft-windows-security-auditing'
  AND lower(channel) = 'security' AND event_id IN (4624, 4625, 4648)
GROUP BY host, event_id, target_user, target_domain, source_ip, logon_type, substatus
ORDER BY event_count DESC;
