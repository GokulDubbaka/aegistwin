-- AegisTwin PostgreSQL Init
-- This runs once when the PostgreSQL container first starts.

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm for fuzzy search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Schema is managed by Alembic migrations.
-- This file only sets up extensions and initial config.

-- Set default timezone
SET timezone = 'UTC';
