-- Prepares an existing local PostgreSQL server for development with the credentials from
-- src/Veil.Api/appsettings.Development.json. Run as a superuser, e.g.:
--   psql -U postgres -f scripts/init-local-postgres.sql
-- (Windows: "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -f scripts\init-local-postgres.sql)
SELECT 'CREATE ROLE veil LOGIN PASSWORD ''veil_dev_password'''
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'veil') \gexec

SELECT 'CREATE DATABASE veil OWNER veil'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'veil') \gexec

SELECT 'CREATE DATABASE veil_test OWNER veil'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'veil_test') \gexec
