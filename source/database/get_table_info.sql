SELECT 
    t.table_ref AS table_name,
    pg_total_relation_size(t.relation) AS table_total_size,
    pg_indexes_size(t.relation) AS table_index_size,
    pg_relation_size(t.relation) AS table_data_size
FROM unnest(
    ARRAY[
        'public.ips',
        'public.ports',
        'public.scaninfo',
        'public.scan_result_batch',
        'public.scan_observation'
    ]
) AS candidate(table_ref)
CROSS JOIN LATERAL (
    SELECT candidate.table_ref, to_regclass(candidate.table_ref) AS relation
) AS t
WHERE t.relation IS NOT NULL;
