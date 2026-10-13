"""Live contract tests. Run only against the dedicated dss-e2e Compose project."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import asyncpg
import httpx
import jwt
import pytest
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-p", "dss-e2e", "-f", "docker-compose.yml", "-f", "compose.test.yml"]
URL = "http://localhost:18080"
DB = f"postgres://postgres:dss-test@localhost:{int(os.getenv('DSS_TEST_DATABASE_PORT', '55432'))}/dss_test?sslmode=disable"
CUSTOMER = "22222222-2222-4222-8222-222222222222"
ADMIN = "11111111-1111-4111-8111-111111111111"
pytestmark = pytest.mark.skipif(os.getenv("DSS_E2E") != "1", reason="requires disposable dss-e2e stack")


def compose(*args, input=None):
    result = subprocess.run(COMPOSE + list(args), cwd=ROOT, input=input,
                            text=True, capture_output=True, timeout=120)
    assert result.returncode == 0, result.stderr[-2000:]
    return result.stdout


def sql(statement, *args):
    async def run():
        connection = await asyncpg.connect(DB)
        try:
            return await connection.fetch(statement, *args)
        finally:
            await connection.close()
    return asyncio.run(run())


def request(method, path, **kwargs):
    return httpx.request(method, URL + path, timeout=20, **kwargs)


def login(username="customer", password="customer123", path="/login", trace=None):
    response = request("POST", path, json={"username": username, "password": password, "device_id": "e2e-device"},
                       headers={"traceparent": trace} if trace else {})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def token():
    return login()


def transfer(token, amount="50.00", sender=CUSTOMER, receiver=ADMIN, path="/api/v1/payments/transfer", headers=None):
    # Preserve the exact JSON number token instead of rounding through float.
    body = json.dumps({"sender_id": sender, "receiver_id": receiver})[:-1] + ',"amount":' + str(amount) + '}'
    authorization = {"Authorization": "Bearer " + token} if token else {}
    return request("POST", path, content=body,
                   headers={"Content-Type": "application/json", **authorization, **(headers or {})})


def balance():
    return sql("SELECT balance FROM accounts WHERE user_id=$1::uuid", CUSTOMER)[0]["balance"]


def ledger_count():
    return sql("SELECT count(*) AS n FROM transactions")[0]["n"]


def reset_balance(value="1000.00"):
    sql("UPDATE accounts SET balance=$1, status='ACTIVE' WHERE user_id=$2::uuid RETURNING balance", Decimal(value), CUSTOMER)


def internal(path, service="account-service", cert="account-service", token=None, extra=None, tls12=False):
    code = '''import httpx, ssl, json, sys
args=json.loads(sys.stdin.read())
context=ssl.create_default_context(cafile='/certs/ca.crt')
context.minimum_version=ssl.TLSVersion.TLSv1_3
if args['tls12']:
 context.minimum_version=ssl.TLSVersion.TLSv1_2
 context.maximum_version=ssl.TLSVersion.TLSv1_2
if args['cert']:
 context.load_cert_chain('/certs/'+args['cert']+'.crt','/certs/'+args['cert']+'.key')
try:
 response=httpx.request('POST' if args['url'].endswith('/transfer') else 'GET',args['url'],verify=context,headers=args['headers'],timeout=5)
 print(json.dumps({'status':response.status_code,'body':response.text}))
except httpx.HTTPError:
 print(json.dumps({'status':0,'body':'transport_refused'}))
'''
    headers = {"Authorization": "Bearer " + token} if token else {}
    headers.update(extra or {})
    output = compose("exec", "-T", "account-service", "python", "-c", code,
                     input=json.dumps({"url": f"https://{service}:{8082 if service == 'account-service' else 8081}" + path,
                                       "cert": cert, "tls12": tls12, "headers": headers}))
    return json.loads(output)


def eventually(check, seconds=35):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = check()
        except httpx.HTTPError:
            result = False
        if result:
            return result
        time.sleep(.5)
    pytest.fail("condition did not become true within deadline")


def test_stack_health_and_public_identity_contract():
    assert request("GET", "/readyz").status_code == 200
    for path in ["/jwks.json", "/.well-known/jwks.json"]:
        assert request("GET", path).json()["keys"][0]["alg"] == "RS256"
    assert request("GET", "/.well-known/openid-configuration").status_code == 200
    assert login(path="/token")
    claims = jwt.decode(login(), options={"verify_signature": False})
    assert claims["sub"] == CUSTOMER and claims["roles"] == ["customer"]
    assert claims["device_id"] == "e2e-device" and claims["exp"] > time.time()
    for service in ["idp", "account-service", "payment-service"]:
        data = json.loads(compose("ps", "--format", "json", service))
        assert not any(port["PublishedPort"] for port in data.get("Publishers") or []), service + " exposes a bypass port"


def test_runtime_certificate_mounts_do_not_expose_other_service_keys():
    for service in ["gateway", "account-service"]:
        files = json.loads(compose("exec", "-T", service, "python", "-c",
                                   "import json,os; print(json.dumps(os.listdir('/certs')))"))
        assert "ca.key" not in files and "payment-service.key" not in files
        if service == "gateway":
            assert set(files) == {"ca.crt", "gateway.crt", "gateway.key"}
        else:
            assert "gateway.key" not in files
    assert compose("exec", "-T", "payment-service", "sh", "-c",
                   "test ! -e /certs/ca.key && test ! -e /certs/gateway.key && test ! -e /certs/account-server.key").strip() == ""


def test_wrong_credentials_and_unknown_users_have_same_reply():
    a = request("POST", "/login", json={"username": "customer", "password": "wrong"})
    b = request("POST", "/login", json={"username": "ghost", "password": "wrong"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_successful_transfer_is_exact_and_recorded_once(token):
    reset_balance()
    before = ledger_count()
    response = transfer(token, "0.01")
    assert response.status_code == 200, response.text
    transaction = response.json()
    assert Decimal(str(transaction["amount"])) == Decimal("0.01")
    assert balance() == Decimal("999.99")
    assert ledger_count() == before + 1
    row = sql("SELECT * FROM transactions WHERE txn_id=$1::uuid", transaction["txn_id"])[0]
    assert row["sender_id"].hex == CUSTOMER.replace("-", "")
    assert row["amount"] == Decimal("0.01")
    response = request("GET", "/api/v1/accounts", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200 and Decimal(response.json()["balance"]) == balance()


def test_documented_payment_alias(token):
    reset_balance()
    assert transfer(token, path="/api/v1/payment").status_code == 200


@pytest.mark.parametrize("amount", ["0", "-1", "0.001", "NaN", "Infinity", "100000000.00", '"50.00"', "garbage"])
def test_invalid_money_never_debits_or_records(token, amount):
    before, rows = balance(), ledger_count()
    response = transfer(token, amount)
    assert response.status_code == 400, response.text
    assert (balance(), ledger_count()) == (before, rows)


@pytest.mark.parametrize("case", ["missing", "tampered", "hs256", "expired", "issuer", "audience", "no_exp"])
def test_gateway_rejects_invalid_tokens(token, case):
    key = dotenv_values(ROOT / ".env")["IDP_RSA_PRIVATE_KEY"].replace("\\n", "\n")
    claims = jwt.decode(token, options={"verify_signature": False})
    header = jwt.get_unverified_header(token)
    candidate = token
    if case == "missing": candidate = ""
    if case == "tampered": candidate = token[:-10] + "aaaaaaaaaa"
    if case == "hs256": candidate = jwt.encode(claims, "untrusted-test-key-which-is-at-least-32-bytes", algorithm="HS256", headers={"kid": header["kid"]})
    if case in {"expired", "issuer", "audience", "no_exp"}:
        if case == "expired": claims["exp"] = int(time.time()) - 60
        if case == "issuer": claims["iss"] = "untrusted"
        if case == "audience": claims["aud"] = ["untrusted"]
        if case == "no_exp": claims.pop("exp")
        candidate = jwt.encode(claims, key, algorithm="RS256", headers={"kid": header["kid"]})
    before, rows = balance(), ledger_count()
    assert transfer(candidate).status_code == 401
    assert (balance(), ledger_count()) == (before, rows)


def test_sender_binding_and_private_reads(token):
    before, rows = balance(), ledger_count()
    assert transfer(token, sender=ADMIN, receiver=CUSTOMER).status_code == 403
    assert request("GET", "/api/v1/accounts/" + ADMIN, headers={"Authorization": "Bearer " + token}).status_code == 403
    assert (balance(), ledger_count()) == (before, rows)


def test_policy_limit_and_failed_deductions(token):
    reset_balance("100000")
    before, rows = balance(), ledger_count()
    assert transfer(token, "50000.01").status_code == 403
    assert (balance(), ledger_count()) == (before, rows)
    reset_balance("10")
    assert transfer(token, "50").status_code == 400
    assert balance() == Decimal("10") and ledger_count() == rows
    sql("UPDATE accounts SET status='SUSPENDED' WHERE user_id=$1::uuid RETURNING status", CUSTOMER)
    assert transfer(token, "1").status_code == 400
    assert balance() == Decimal("10") and ledger_count() == rows
    reset_balance()


@pytest.mark.parametrize("service", ["account-service", "payment-service"])
def test_transport_and_probe_identity(service, token):
    assert internal("/healthz", service, cert=None)["status"] == 0
    assert internal("/healthz", service, tls12=True)["status"] == 0
    path = "/api/v1/accounts/" + CUSTOMER if service == "account-service" else "/api/v1/payments/transfer"
    assert internal(path, service, cert="probe", token=token)["status"] == 403
    assert internal(path, service, cert=None, token=token,
                    extra={"X-Forwarded-Client-Cert": "gateway", "X-Client-Cert-Present": "true"})["status"] == 0


def test_backend_transport_refusals_reach_the_audit_trail():
    for service in ["account-service", "payment-service"]:
        assert internal("/healthz", service, cert=None)["status"] == 0
        def audited():
            response = httpx.get("http://localhost:18088/v1/audit/events", params={
                "service": service, "reason": "no_client_certificate", "decision": "DENY", "limit": 5})
            return response.status_code == 200 and bool(response.json()["events"])
        eventually(audited)


def test_account_revalidates_token_and_money(token):
    assert internal("/api/v1/accounts/" + CUSTOMER, token="forged")["status"] == 401
    before, rows = balance(), ledger_count()
    response = request("POST", "/api/v1/accounts/deduct", headers={"Authorization": "Bearer " + token},
                       json={"user_id": CUSTOMER, "amount": "0.001"})
    assert response.status_code == 422
    assert (balance(), ledger_count()) == (before, rows)


def test_concurrent_transfers_cannot_overdraw(token):
    reset_balance("100")
    before = ledger_count()
    with ThreadPoolExecutor(max_workers=12) as executor:
        responses = list(executor.map(lambda _: transfer(token, "10"), range(20)))
    assert sum(r.status_code == 200 for r in responses) == 10, [r.status_code for r in responses]
    assert sum(r.status_code == 400 for r in responses) == 10
    assert balance() == Decimal("0")
    assert ledger_count() == before + 10
    reset_balance()


@pytest.mark.parametrize("dependency, expected", [("policy-engine", 403), ("account-service", 400)])
def test_dependency_outages_fail_closed_and_recover(token, dependency, expected):
    before, rows = balance(), ledger_count()
    compose("stop", dependency)
    try:
        assert transfer(token, "1").status_code == expected
        assert (balance(), ledger_count()) == (before, rows)
    finally:
        compose("up", "-d", "--wait", dependency)
    assert transfer(token, "1").status_code == 200


def test_ledger_is_append_only():
    for statement in ["UPDATE transactions SET amount=1", "DELETE FROM transactions", "TRUNCATE transactions"]:
        with pytest.raises(asyncpg.PostgresError):
            sql(statement)


def test_audit_and_spans_join_the_live_flow(token):
    trace_id = secrets.token_hex(16)
    trace = "00-" + trace_id + "-" + secrets.token_hex(8) + "-01"
    login(trace=trace)
    reset_balance()
    response = transfer(token, "1", headers={"traceparent": trace})
    assert response.status_code == 200
    assert response.headers["traceparent"].split("-")[1] == trace_id

    def joined():
        response = httpx.get("http://localhost:18088/v1/audit/traces/" + trace_id, timeout=5)
        if response.status_code != 200: return False
        flow = response.json()["trace"]
        services = {span["service"] for span in flow["spans"]}
        events = {event["service"] for event in flow["events"]}
        return flow if {"gateway", "idp", "payment-service", "account-service"} <= services and {"gateway", "idp", "payment-service", "account-service", "policy-engine"} <= events else False
    # OPA records carry traceparent in payment's policy context.
    flow = eventually(joined)
    assert len(flow["spans"]) >= 6
    assert httpx.get("http://localhost:18088/dashboard").status_code == 200
    assert httpx.post("http://localhost:18088/v1/audit/events", json={"decision": "DENY"}).status_code == 401
    assert httpx.get("http://localhost:13300/api/health").status_code == 200
    datasource = httpx.get("http://localhost:13300/api/datasources/uid/loki").json()
    assert datasource["jsonData"]["derivedFields"][0]["url"] == "http://localhost:26686/trace/${__value.raw}"
    eventually(lambda: "gateway" in httpx.get("http://localhost:13100/loki/api/v1/label/service/values").json().get("data", []))
    eventually(lambda: "gateway" in httpx.get("http://localhost:26686/api/services").json().get("data", []))


def test_restart_preserves_balances_and_ledger(token):
    before, rows = balance(), ledger_count()
    compose("restart", "idp", "account-service", "payment-service")
    eventually(lambda: request("GET", "/readyz").status_code == 200)
    assert (balance(), ledger_count()) == (before, rows)
    assert request("GET", "/api/v1/accounts", headers={"Authorization": "Bearer " + token}).status_code == 200


def test_gateway_global_rate_limit_and_recovery():
    compose("restart", "gateway")
    eventually(lambda: request("GET", "/healthz").status_code == 200)
    responses = [request("GET", "/unregistered") for _ in range(125)]
    assert any(response.status_code == 429 for response in responses)
    throttled = next(response for response in responses if response.status_code == 429)
    assert int(throttled.headers["retry-after"]) > 0
    compose("restart", "gateway")
    eventually(lambda: request("GET", "/readyz").status_code == 200)
    assert request("GET", "/unregistered").status_code == 404
