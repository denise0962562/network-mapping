INSERT INTO 
    system_status
        (server_run_time, cpu, ram, disk, db_postgresql, db_elasticsearch, network)
VALUES
    ($1, $2, $3, $4, $5, $6, $7)
;
