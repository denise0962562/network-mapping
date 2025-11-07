SELECT 
    relname AS table_name,
    pg_total_relation_size(relid) AS total_size,
    pg_relation_size(relid) AS data_size,
    pg_indexes_size(relid) AS index_size
FROM pg_catalog.pg_statio_user_tables 
WHERE relname = ANY($1);