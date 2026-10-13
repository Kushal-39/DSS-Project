#!/usr/bin/env python3
"""Presentation helpers restricted to the disposable dss-e2e stack."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time

import asyncpg
import httpx
import jwt
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ['docker', 'compose', '-p', 'dss-e2e', '-f', 'docker-compose.yml', '-f', 'compose.test.yml']
BASE = 'http://127.0.0.1:18080'
CUSTOMER = '22222222-2222-4222-8222-222222222222'
ADMIN = '11111111-1111-4111-8111-111111111111'


def pretty(value):
    print(json.dumps(value, indent=2, default=str))


def execute(code, payload):
    result = subprocess.run(COMPOSE + ['exec', '-T', 'account-service', 'python', '-c', code],
                            cwd=ROOT, input=json.dumps(payload), text=True, capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError('Container helper failed: ' + result.stderr[-800:])
    return json.loads(result.stdout)


async def database(args):
    connection = await asyncpg.connect(f"postgres://postgres:dss-test@127.0.0.1:{int(os.getenv('DSS_TEST_DATABASE_PORT', '55432'))}/dss_test?sslmode=disable")
    try:
        assert await connection.fetchval('SELECT current_database()') == 'dss_test'
        if args.command == 'reset':
            from decimal import Decimal
            await connection.execute("UPDATE accounts SET balance=$1,status='ACTIVE' WHERE user_id=$2::uuid",
                                     Decimal(args.balance), CUSTOMER)
        accounts = await connection.fetch('SELECT user_id,balance,status FROM accounts ORDER BY user_id')
        rows = await connection.fetchval('SELECT count(*) FROM transactions')
        pretty({'accounts': [dict(row) for row in accounts], 'ledger_rows': rows})
    finally:
        await connection.close()


def policy(case):
    import copy
    base = {'input': {'subject': {'user_id': CUSTOMER, 'roles': ['customer']},
                      'action': 'TRANSFER', 'resource': 'account_' + CUSTOMER,
                      'context': {'amount': 50, 'ip_address': '192.0.2.10', 'mTLS_verified': True}}}
    data = copy.deepcopy(base)
    expected = case in {'allow', 'boundary', 'admin', 'read-own'}
    if case == 'boundary': data['input']['context']['amount'] = 50000
    if case == 'over-limit': data['input']['context']['amount'] = 50000.01
    if case == 'zero': data['input']['context']['amount'] = 0
    if case == 'negative': data['input']['context']['amount'] = -1
    if case == 'string-amount': data['input']['context']['amount'] = '50.00'
    if case == 'no-mtls': data['input']['context']['mTLS_verified'] = False
    if case == 'guest': data['input']['subject']['roles'] = ['guest']
    if case == 'unknown-action': data['input']['action'] = 'WITHDRAW'
    if case == 'empty': data = {'input': {}}
    if case == 'flat': data = {'input': {'subject': CUSTOMER, 'roles': ['customer'], 'action': 'TRANSFER', 'context': base['input']['context']}}
    if case == 'unwrapped': data = data['input']
    if case in {'admin', 'admin-no-mtls'}:
        data['input']['subject'] = {'user_id': ADMIN, 'roles': ['admin']}
        data['input']['context']['amount'] = 60000
        if case == 'admin-no-mtls': data['input']['context']['mTLS_verified'] = False
    if case in {'read-own', 'read-other'}:
        data['input']['action'] = 'READ_ACCOUNT'
        data['input']['resource'] = 'account_' + (CUSTOMER if case == 'read-own' else ADMIN)
    code = """import json,sys,httpx
payload=json.loads(sys.stdin.read())
r=httpx.post('http://policy-engine:8181/v1/data/authz/allow',json=payload,timeout=5)
print(json.dumps({'http_status':r.status_code,'response':r.json()}))
"""
    result = execute(code, data)
    pretty({'case': case, 'request': data, **result, 'expected_allow': expected})
    assert result['http_status'] == 200 and result['response'].get('result', {}).get('allow') is expected


def token_variant(args):
    token = os.environ.get(args.token_env, '')
    if not token: raise RuntimeError('Set ' + args.token_env + ' with the login step first')
    claims = jwt.decode(token, options={'verify_signature': False})
    header = jwt.get_unverified_header(token)
    if args.case == 'tampered':
        claims['roles'] = ['admin']
        import base64
        body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        print(token.split('.')[0] + '.' + body + '.' + token.split('.')[2])
        return
    if args.case == 'hs256':
        print(jwt.encode(claims, 'deliberately-untrusted-demo-key-at-least-32-bytes', algorithm='HS256', headers={'kid': header['kid']}))
        return
    if args.case == 'expired': claims['exp'] = int(time.time()) - 60
    if args.case == 'wrong-issuer': claims['iss'] = 'untrusted-issuer'
    if args.case == 'wrong-audience': claims['aud'] = ['untrusted-audience']
    if args.case == 'no-exp': claims.pop('exp', None)
    # Read signing material in memory only; never print it or send it to a container.
    key = dotenv_values(ROOT / '.env')['IDP_RSA_PRIVATE_KEY'].replace('\\n', '\n')
    print(jwt.encode(claims, key, algorithm='RS256', headers={'kid': header['kid']}))


def transport(args):
    code = """import json,sys,ssl,httpx,tempfile
args=json.loads(sys.stdin.read())
ctx=ssl.create_default_context(cafile='/certs/ca.crt')
ctx.minimum_version=ssl.TLSVersion.TLSv1_3
if args['tls12']:
 ctx.minimum_version=ssl.TLSVersion.TLSv1_2
 ctx.maximum_version=ssl.TLSVersion.TLSv1_2
if args['identity']=='untrusted':
 from cryptography import x509
 from cryptography.x509.oid import NameOID
 from cryptography.hazmat.primitives.asymmetric import ec
 from cryptography.hazmat.primitives import hashes,serialization
 from datetime import datetime,timedelta,timezone
 key=ec.generate_private_key(ec.SECP256R1())
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'untrusted-demo-client')])
 now=datetime.now(timezone.utc)
 cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).sign(key,hashes.SHA256())
 tmp=tempfile.TemporaryDirectory()
 open(tmp.name+'/cert','wb').write(cert.public_bytes(serialization.Encoding.PEM))
 open(tmp.name+'/key','wb').write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 ctx.load_cert_chain(tmp.name+'/cert',tmp.name+'/key')
elif args['identity']!='none':
 ctx.load_cert_chain('/certs/'+args['identity']+'.crt','/certs/'+args['identity']+'.key')
try:
 r=httpx.request(args['method'],args['url'],verify=ctx,headers=args['headers'],timeout=6)
 try: body=r.json()
 except ValueError: body=r.text
 print(json.dumps({'status':r.status_code,'body':body}))
except httpx.HTTPError as error:
 print(json.dumps({'status':0,'result':'TLS connection refused','error_type':type(error).__name__}))
"""
    headers = {}
    if args.token_env:
        headers['Authorization'] = 'Bearer ' + os.environ[args.token_env]
    if args.spoof:
        headers.update({'X-Forwarded-Client-Cert': 'gateway', 'X-Client-Cert-Present': 'true'})
    port = 8082 if args.service == 'account-service' else 8081
    result = execute(code, {'url': f'https://{args.service}:{port}' + args.path,
                            'identity': args.identity, 'tls12': args.tls12,
                            'method': args.method, 'headers': headers})
    pretty(result)
    assert result['status'] == args.expect, f"Expected {args.expect}, got {result['status']}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('state')
    reset = sub.add_parser('reset')
    reset.add_argument('--balance', default='1000.00')
    request = sub.add_parser('http')
    request.add_argument('method')
    request.add_argument('path')
    request.add_argument('--token-env')
    request.add_argument('--data')
    request.add_argument('--trace')
    request.add_argument('--expect', type=int, required=True)
    pol = sub.add_parser('policy')
    pol.add_argument('case', choices=['allow','boundary','over-limit','zero','negative','string-amount','no-mtls','guest','unknown-action','empty','flat','unwrapped','admin','admin-no-mtls','read-own','read-other'])
    tok = sub.add_parser('token')
    tok.add_argument('case', choices=['tampered','hs256','expired','wrong-issuer','wrong-audience','no-exp'])
    tok.add_argument('--token-env', default='TOKEN')
    mtls = sub.add_parser('mtls')
    mtls.add_argument('service', choices=['account-service','payment-service'])
    mtls.add_argument('--identity', choices=['account-service','probe','none','untrusted'], default='account-service')
    mtls.add_argument('--tls12', action='store_true')
    mtls.add_argument('--spoof', action='store_true')
    mtls.add_argument('--method', default='GET')
    mtls.add_argument('--path', default='/healthz')
    mtls.add_argument('--token-env')
    mtls.add_argument('--expect', type=int, required=True)
    args = parser.parse_args()
    if args.command in {'state','reset'}: asyncio.run(database(args))
    elif args.command == 'policy': policy(args.case)
    elif args.command == 'token': token_variant(args)
    elif args.command == 'mtls': transport(args)
    else:
        headers = {'Content-Type': 'application/json'}
        if args.token_env: headers['Authorization'] = 'Bearer ' + os.environ[args.token_env]
        if args.trace: headers['traceparent'] = args.trace
        response = httpx.request(args.method, BASE + args.path, headers=headers, content=args.data, timeout=20)
        try: body = response.json()
        except ValueError: body = response.text
        if isinstance(body, dict):
            body = {key: '[token omitted]' if key in {'token','access_token'} else value for key,value in body.items()}
        pretty({'status':response.status_code,'body':body,'traceparent':response.headers.get('traceparent')})
        assert response.status_code == args.expect, f'Expected {args.expect}, got {response.status_code}'


if __name__ == '__main__':
    main()
