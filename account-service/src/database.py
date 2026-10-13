"""Database access, connection pooling, and schema migration runner."""

import asyncio
import logging
from decimal import Decimal
from pathlib import Path
from typing import Optional
from uuid import UUID

import asyncpg

from src.config import settings

logger = logging.getLogger("account-service")


class Database:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self, max_retries: int = 30, retry_delay: float = 1.0):
        """Connect to PostgreSQL with retry logic (supports Supabase startup delays)."""
        dsn = settings.DATABASE_URL
        # Normalize postgresql scheme if needed
        if dsn.startswith("postgres://"):
            dsn = "postgresql://" + dsn[len("postgres://"):]

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connecting to database (attempt {attempt}/{max_retries})...")
                self.pool = await asyncpg.create_pool(
                    dsn=dsn,
                    min_size=2,
                    max_size=10,
                    timeout=10.0,
                    command_timeout=10.0,
                )
                # Verify connection with ping
                async with self.pool.acquire() as conn:
                    await conn.fetchval("SELECT 1")
                logger.info("Database connection established successfully.")
                return
            except Exception as e:
                logger.warning(f"Database connection attempt {attempt} failed: {e}")
                if attempt == max_retries:
                    logger.error("Exceeded maximum database connection attempts. Exiting.")
                    raise
                await asyncio.sleep(retry_delay)

    async def disconnect(self):
        """Close database connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed.")

    async def is_healthy(self) -> bool:
        """Check if database connection is responsive."""
        if not self.pool:
            return False
        try:
            async with self.pool.acquire() as conn:
                res = await conn.fetchval("SELECT 1")
                return res == 1
        except Exception:
            return False

    async def run_migrations(self, migrations_dir: Optional[Path] = None):
        """Run SQL migrations and seed scripts idempotently (docs/database.md §4)."""
        if not self.pool:
            raise RuntimeError("Database not connected")

        if migrations_dir is None:
            migrations_dir = Path(__file__).resolve().parent.parent / "migrations"

        if not migrations_dir.exists():
            raise RuntimeError("Account migrations directory is missing")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(428001)")
                # Migration tracking table
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS _account_schema_migrations (
                        version VARCHAR(255) PRIMARY KEY,
                        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                """)

                # Run up migrations in order
                up_files = sorted(migrations_dir.glob("*.up.sql"))
                for file_path in up_files:
                    version = file_path.name
                    already_applied = await conn.fetchval(
                        "SELECT 1 FROM _account_schema_migrations WHERE version = $1", version
                    )
                    if not already_applied:
                        logger.info(f"Applying migration: {version}")
                        sql_content = file_path.read_text(encoding="utf-8")
                        await conn.execute(sql_content)
                        await conn.execute(
                            "INSERT INTO _account_schema_migrations (version) VALUES ($1)", version
                        )
                        logger.info(f"Applied migration: {version}")
                    else:
                        logger.debug(f"Migration {version} already applied.")

                # Run seed script if present
                seed_file = migrations_dir / "seed.sql"
                if seed_file.exists():
                    logger.info("Executing database seed script...")
                    seed_sql = seed_file.read_text(encoding="utf-8")
                    await conn.execute(seed_sql)
                    logger.info("Database seed script completed.")

    async def get_account(self, user_id: UUID) -> Optional[dict]:
        """Fetch account record by user_id."""
        if not self.pool:
            raise RuntimeError("Database not connected")

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT user_id, balance, status FROM accounts WHERE user_id = $1",
                user_id,
            )
            if row:
                return dict(row)
            return None

    async def deduct_balance(self, user_id: UUID, amount: Decimal) -> Optional[Decimal]:
        """
        Atomically deduct amount from user account balance if sufficient funds exist and account is ACTIVE.
        Returns the new remaining balance, or None if conditions not met.
        """
        if not self.pool:
            raise RuntimeError("Database not connected")

        query = """
            UPDATE accounts
            SET balance = balance - $1
            WHERE user_id = $2 AND balance >= $1 AND status = 'ACTIVE'
            RETURNING balance;
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                remaining = await conn.fetchval(query, amount, user_id)
                return remaining


db = Database()
