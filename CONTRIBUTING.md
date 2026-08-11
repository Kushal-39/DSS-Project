# Contributing to the Zero-Trust Distributed System

## 1. The Monorepo Law
This repository contains all six micro-domains. You only touch the directory assigned to your role. 

* `/idp` (Identity Provider)
* `/gateway` (API Gateway)
* `/policy-engine` (OPA/ABAC)
* `/account-service` (Account Backend)
* `/payment-service` (Payment Backend)
* `/telemetry` (Audit & Logs)

If you are working on the network gateway, you do not randomly modify Go files in the backend service directories. Stay in your lane. Communicate contract changes via standard API definitions, not by hacking someone else's folder.

## 2. Git Workflow (No Direct Commits to Main)
The `main` branch is locked. If you try to push directly to it, the repository will reject your commit. 

* **Step 1:** Pull the latest `main`.
* **Step 2:** Create a feature branch scoped to your component. Use a sane naming convention like `feat/gateway-mtls` or `fix/payment-auth`.
* **Step 3:** Write your code.
* **Step 4:** Open a Pull Request (PR) on GitHub.

## 3. The Secrets Management Protocol (DO NOT SKIP)

* **Never commit a `.env` file.** If you push actual database passwords or JWT secrets to this repository, your PR will be closed
* **Use `.env.example`:** We have a `.env.example` file in the root directory. It contains dummy values. 
* **Local Setup:** When you clone this repository, duplicate `.env.example`, rename the copy to `.env`, and paste the real credentials that were shared securely via the team group chat. 
* The `.gitignore` file is already configured to ignore `.env`. Do not tamper with it.
### 3.a git-crypt
The `.env` file is committed to the repository, but it is encrypted using `git-crypt`. If you try to read it on GitHub, it will look like binary garbage.

* **Step 1:** Install `git-crypt` on your system.
* **Step 2:** Clone the repository. The `.env` file will currently be locked.
* **Step 3:** Get the `zerotrust-key.key` file from Kushal. Do not upload this key anywhere public.
* **Step 4:** Run `git-crypt unlock /path/to/zerotrust-key.key` in the project root.
* **Step 5:** You now have the plaintext `.env` file. You can run `docker compose up --build`.

If you need to add a new environment variable, just edit the decrypted `.env` file and commit it normally. `git-crypt` handles the encryption automatically before it pushes.

## 4. The Docker Compose Mandate
Before you even think about clicking "Create Pull Request", you must run this exact command on your local machine:

```bash
docker compose up --build

```

If the build crashes, your code is garbage. Fix it. The containers must spin up cleanly and communicate over the internal Docker network.

## 5. Pull Request Reviews

* You need at least one approval from another team member before you can hit merge.
* **Reviewers:** Check if the PR actually implements the standard project interfaces. Are they checking the JWT? Are they enforcing mTLS? Are they pinging the policy engine? If someone tries to bypass the API gateway to call a service directly, reject the PR immediately.

## 6. Coding Standards

* Write clean, readable code.
* Format your code properly before committing.
* Add comments only when your logic is actually complex.

Merge conflicts will inevitably happen. Communicate with each other face to face instead of blindly force-pushing over someone else's hard work.


