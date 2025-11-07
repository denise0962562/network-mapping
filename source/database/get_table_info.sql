SELECT 
    t.table_ref AS table_name,
    pg_total_relation_size(t.table_ref::regclass) AS table_total_size,
    pg_indexes_size(t.table_ref::regclass) AS table_index_size,
    pg_relation_size(t.table_ref::regclass) AS table_data_size
FROM unnest(
    ARRAY[
        'public.ips',
        'public.ports',
        'public.scaninfo'
    ]
) AS t(table_ref);
