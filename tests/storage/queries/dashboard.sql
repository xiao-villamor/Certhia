SELECT severity_id,sum(total) FROM dashboard_counts GROUP BY severity_id ORDER BY severity_id;
