#!/usr/bin/env python3
"""
AppScan 360 DAST client - start a scan or rescan from any automation,
synchronously (wait for results, download report, apply a severity gate)
or asynchronously (initiate and exit).

Mirrors the alexhcl/appscan360-dast-action behavior over the same
/api/v4 REST API. Standard library only - no pip installs needed.

Usage
  Sync scan (wait + gate):
    python3 appscan_dast.py --base-url https://ascp.appscan.local \
        --app-id <APP_GUID> --starting-url https://staging.yourapp.com \
        --mode sync --fail-on High

  Async scan (initiate and exit immediately):
    python3 appscan_dast.py --base-url https://ascp.appscan.local \
        --app-id <APP_GUID> --starting-url https://staging.yourapp.com \
        --mode async

  Rescan the application's newest DAST scan:
    python3 appscan_dast.py --base-url https://ascp.appscan.local \
        --app-id <APP_GUID> --rescan-latest --mode sync

Credentials: --key-id/--key-secret, or env ASOC_KEY_ID / ASOC_KEY_SECRET.

Exit codes
  0 ok (async: initiated; sync: scan Ready and gate passed or no gate)
  1 gate failed (issues at/above --fail-on)
  2 scan Failed/Stopped on the server
  3 timeout waiting for the scan (sync)
  4 connection/API error
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]


class Client:
    def __init__(self, base_url, key_id, key_secret, insecure=False):
        self.base = base_url.rstrip("/")
        self.api = self.base + "/api/v4"
        self.token = None
        self.ctx = ssl._create_unverified_context() if insecure else None
        self.key_id, self.key_secret = key_id, key_secret

    def _req(self, method, url, body=None, raw=False):
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=120) as r:
            payload = r.read()
        if raw:
            return payload
        return json.loads(payload) if payload else {}

    def login(self):
        out = self._req("POST", self.api + "/Account/ApiKeyLogin",
                        {"KeyId": self.key_id, "KeySecret": self.key_secret})
        self.token = out.get("Token") or out.get("token")
        if not self.token:
            raise RuntimeError("login returned no token")

    def scans_for_app(self, app_id):
        out = self._req("GET", self.api + "/Scans?%24filter=AppId%20eq%20" + app_id)
        return out.get("Items") or []

    def latest_dast_scan(self, app_id):
        scans = [s for s in self.scans_for_app(app_id)
                 if s.get("Technology") in (None, "DynamicAnalyzer")]
        scans.sort(key=lambda s: s.get("CreatedAt") or "", reverse=True)
        return scans[0] if scans else None

    def create_scan(self, app_id, starting_url, scan_name, optimization,
                    login_user=None, login_password=None):
        body = {
            "IncludeVerifiedDomains": True,
            "ScanConfiguration": {
                "Target": {"StartingUrl": starting_url},
                "Tests": {"TestOptimizationLevel": optimization},
            },
            "UseAutomaticTimeout": True,
            "MaxRequestsIn": 10,
            "MaxRequestsTimeFrame": 1000,
            "OnlyFullResults": True,
            "FullyAutomatic": True,
            "ScanName": scan_name,
            "EnableMailNotification": False,
            "Locale": "en-US",
            "AppId": app_id,
            "Execute": True,
            "Personal": False,
            "ClientType": "python-dast-client",
        }
        if login_user:
            body["ScanConfiguration"]["Login"] = {
                "LoginMethod": "AutomaticLogin",
                "Username": login_user, "Password": login_password or "",
            }
        out = self._req("POST", self.api + "/Scans/Dast", body)
        return out.get("Id")

    def rescan(self, scan_id):
        out = self._req("POST", self.api + "/Scans/%s/Executions" % scan_id, {})
        return out.get("Id")

    def rename_scan(self, scan_id, name):
        self._req("PUT", self.api + "/Scans/" + scan_id, {"Name": name})

    def executions(self, scan_id):
        out = self._req("GET", self.api + "/Scans/%s/Executions" % scan_id)
        return out.get("Items") if isinstance(out, dict) else out

    def issue_counts(self, scan_id):
        url = (self.api + "/Issues/Scan/" + scan_id +
               "?applyPolicies=None&%24filter=Status%20eq%20%27Open%27%20or%20"
               "Status%20eq%20%27InProgress%27%20or%20Status%20eq%20%27Reopened%27"
               "&%24apply=groupby%28%28Status%2CSeverity%29%2Caggregate%28%24count%20as%20N%29%29")
        items = self._req("GET", url).get("Items") or []
        counts = {s: 0 for s in SEVERITY_ORDER}
        for i in items:
            sev = i.get("Severity")
            if sev in counts:
                counts[sev] += int(i.get("N", i.get("Count", 0)) or 0)
        return counts

    def download_report(self, scan_id, out_file):
        rep = self._req("POST", self.api + "/Reports/Security/Scan/" + scan_id,
                        {"Configuration": {"Summary": True, "Issues": True,
                                           "Details": True, "Overview": True},
                         "OdataFilter": "", "ApplyPolicies": "None"})
        rep_id = rep.get("Id")
        while True:
            time.sleep(5)
            st = self._req("GET", self.api + "/Reports?%24filter=Id%20eq%20" + rep_id)
            item = (st.get("Items") or [{}])[0]
            if item.get("Status") == "Ready":
                break
            print("  report progress: %s%%" % item.get("Progress", "?"))
        html = self._req("GET", self.api + "/Reports/%s/Download" % rep_id, raw=True)
        with open(out_file, "wb") as f:
            f.write(html)
        return out_file


def pick_execution(execs, exec_id):
    if not execs:
        return None
    if not isinstance(execs, list):
        return execs
    if exec_id:
        for e in execs:
            if e.get("Id") == exec_id:
                return e
    return sorted(execs, key=lambda e: e.get("CreatedAt") or "", reverse=True)[0]


def main():
    ap = argparse.ArgumentParser(description="AppScan 360 DAST client (sync/async)")
    ap.add_argument("--base-url", required=True, help="AppScan 360 server, e.g. https://ascp.appscan.local")
    ap.add_argument("--key-id", default=os.environ.get("ASOC_KEY_ID"))
    ap.add_argument("--key-secret", default=os.environ.get("ASOC_KEY_SECRET"))
    ap.add_argument("--app-id", required=True, help="application GUID")
    ap.add_argument("--mode", choices=["sync", "async"], default="sync",
                    help="sync = wait for results, download report, apply gate; "
                         "async = initiate the scan and exit immediately (default: sync)")
    ap.add_argument("--rescan-latest", action="store_true",
                    help="rescan the app's newest DAST scan instead of creating one")
    ap.add_argument("--scan-id", default="", help="with --rescan-latest: rescan exactly this scan")
    ap.add_argument("--starting-url", default="", help="target URL (new-scan mode)")
    ap.add_argument("--scan-name", default="", help="scan name (new scan; best-effort rename on rescan)")
    ap.add_argument("--optimization", default="Fastest",
                    choices=["NoOptimization", "Fast", "Faster", "Fastest"])
    ap.add_argument("--login-user", default="")
    ap.add_argument("--login-password", default=os.environ.get("ASOC_LOGIN_PASSWORD", ""))
    ap.add_argument("--timeout-minutes", type=int, default=360)
    ap.add_argument("--fail-on", default="", choices=["", *SEVERITY_ORDER],
                    help="sync mode: exit 1 if open issues at/above this severity")
    ap.add_argument("--report-file", default="AppScan_Security_Report.html")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS validation (testing only - prefer trusting the CA)")
    a = ap.parse_args()

    if not a.key_id or not a.key_secret:
        sys.exit("credentials missing: pass --key-id/--key-secret or set ASOC_KEY_ID/ASOC_KEY_SECRET")

    c = Client(a.base_url, a.key_id, a.key_secret, a.insecure)
    try:
        c.login()
        print("login ok: %s" % c.api)

        exec_id = None
        if a.rescan_latest:
            scan_id = a.scan_id
            if not scan_id:
                latest = c.latest_dast_scan(a.app_id)
                if not latest:
                    sys.exit("no existing DAST scan to rescan for this application")
                scan_id = latest["Id"]
                print("rescanning latest scan: %s (%s)" % (latest.get("Name"), scan_id))
            if a.scan_name:
                try:
                    c.rename_scan(scan_id, a.scan_name)
                    print("scan renamed to: %s" % a.scan_name)
                except Exception as e:
                    print("warning: rename failed (%s) - execution keeps the stored name" % e)
            exec_id = c.rescan(scan_id)
            if not exec_id:
                sys.exit("rescan returned no execution id")
            print("execution started: %s" % exec_id)
        else:
            if not a.starting_url:
                sys.exit("--starting-url is required to create a new scan")
            scan_id = c.create_scan(a.app_id, a.starting_url,
                                    a.scan_name or "python-dast-client",
                                    a.optimization, a.login_user, a.login_password)
            if not scan_id:
                sys.exit("scan creation returned no scan id")
            print("scan created: %s" % scan_id)

        scan_url = "%s/main/myapps/%s/scans/%s" % (c.base, a.app_id, scan_id)
        print("scan view: %s" % scan_url)

        if a.mode == "async":
            print("async mode: scan is running on the server; exiting.")
            return 0

        # ---- sync: poll until Ready / Failed / timeout ----
        deadline = time.time() + a.timeout_minutes * 60
        status = ""
        while time.time() < deadline:
            e = pick_execution(c.executions(scan_id), exec_id)
            status = (e or {}).get("Status", "")
            if status in ("Ready", "Failed", "Stopped"):
                break
            print("[%s] status: %s" % (time.strftime("%H:%M:%S"), status or "?"))
            time.sleep(30)
        if status in ("Failed", "Stopped"):
            print("scan ended with status %s - see %s" % (status, scan_url))
            return 2
        if status != "Ready":
            print("timed out after %d min (status: %s) - scan continues server-side" %
                  (a.timeout_minutes, status))
            return 3
        print("scan completed.")

        counts = c.issue_counts(scan_id)
        total = sum(counts.values())
        print("open issues: total=%d  %s" %
              (total, "  ".join("%s=%d" % (s, counts[s]) for s in reversed(SEVERITY_ORDER))))

        try:
            f = c.download_report(scan_id, a.report_file)
            print("report saved: %s" % f)
        except Exception as e:
            print("warning: report download failed: %s" % e)

        if a.fail_on:
            threshold = SEVERITY_ORDER.index(a.fail_on)
            bad = sum(counts[s] for s in SEVERITY_ORDER[threshold:])
            if bad > 0:
                print("GATE FAILED: %d issue(s) at or above %s" % (bad, a.fail_on))
                return 1
            print("gate passed: no issues at or above %s" % a.fail_on)
        return 0

    except urllib.error.HTTPError as e:
        print("API error %s %s: %s" % (e.code, e.reason, e.read().decode(errors="replace")[:500]))
        return 4
    except urllib.error.URLError as e:
        print("connection error: %s" % e.reason)
        return 4


if __name__ == "__main__":
    sys.exit(main())
