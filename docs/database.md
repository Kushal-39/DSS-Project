# Database Management & Migrations

This project uses a single shared Supabase PostgreSQL instance for local development. However, we are building a distributed system. You cannot treat this like a monolithic database where every service reads every table.

Read these rules before you write a single SQL query.

## 1. No Manual Schema Changes
Do not log into the Supabase web UI to manually click "Create Table" or add columns. If you do this, the rest of the team will not have your changes, and the application will immediately crash on their machines. All database changes must be tracked in version control through migration scripts.

## 2. Database-per-Service Architecture
Microservices do not share database tables. Period. 
* The **Account Service** owns the `users` and `accounts` tables.
* The **Payment Service** owns the `transactions` and `ledgers` tables.
* The **Identity Provider (IdP)** owns the `credentials` tables.

If the Payment Service needs to verify if a user account exists, it makes an API call over mTLS to the Account Service. It does not run a SQL `SELECT` query on the Account Service's tables. Breaking this rule defeats the entire purpose of the Zero-Trust architecture.

## 3. Writing Migrations
Schema changes are managed using SQL migration files. Every backend service must have a `migrations/` directory at its root. 

When you need a new table, you write two files:
1. **The UP script:** Creates the table or adds the column.
   `001_create_accounts.up.sql`
2. **The DOWN script:** Drops the table or removes the column (for rollbacks).
   `001_create_accounts.down.sql`

## 4. Executing Migrations in Docker
Migrations must run automatically when your container starts, before the main web server boots up. 

* **For Go Services:** Use `golang-migrate`. If Anupam is writing the backend in Go, the `Dockerfile` should install the migrate CLI and run it against the `DATABASE_URL` environment variable on startup.
* **For Python Services:** Use `Alembic` or a lightweight raw SQL executor in your startup script.

## 5. Environment Variables
The actual database connection string is stored in your local `.env` file, which is encrypted in this repository using `git-crypt`. If your code needs to talk to the database, read the `DATABASE_URL` environment variable. Do not hardcode credentials anywhere in your application logic.