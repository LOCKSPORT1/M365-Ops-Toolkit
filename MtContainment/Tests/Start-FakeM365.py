"""
Graph test double for MtContainment.

Serves a deliberately realistic business email compromise scenario so the
investigation, findings engine and containment sequencing can be exercised
end to end without a tenant:

  - an inbox rule named "." that forwards externally and files mail into RSS Feeds
  - a Microsoft Authenticator method registered two days ago
  - an unverified application holding Mail.ReadWrite, Mail.Send and offline_access
  - a successful IMAP4 sign-in from a second country
  - a directory audit entry showing security info registration
  - Identity Protection reporting the user at high risk
  - the account synced from on-premises AD, to exercise the hybrid warning

Writes return 204 and are recorded, so the test can assert what containment
actually called.

    python3 Start-FakeM365.py       # listens on 127.0.0.1:8099
"""

import json
import re
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlparse

PORT = 8099
USER_ID = "7f3c1a90-5d21-4b8e-9a44-11c2e6d70b31"
UPN = "jdoe@contoso.com"

WRITES = []


def iso(delta_days=0, delta_hours=0):
    stamp = datetime.now(timezone.utc) + timedelta(days=delta_days, hours=delta_hours)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


USER = {
    "id": USER_ID,
    "userPrincipalName": UPN,
    "displayName": "Jordan Doe",
    "mail": UPN,
    "accountEnabled": True,
    "createdDateTime": iso(-900),
    "lastPasswordChangeDateTime": iso(-210),
    "userType": "Member",
    "jobTitle": "Accounts Payable Specialist",
    "department": "Finance",
    "officeLocation": "HQ",
    "onPremisesSyncEnabled": True,
    "onPremisesSamAccountName": "jdoe",
    "proxyAddresses": ["SMTP:jdoe@contoso.com"],
    "signInSessionsValidFromDateTime": iso(-210),
}

DOMAINS = {"value": [{"id": "contoso.com", "isVerified": True},
                     {"id": "contoso.mail.onmicrosoft.com", "isVerified": True}]}

RSS_FOLDER_ID = "AAMkAGZmZjRSSFEED"

MESSAGE_RULES = {
    "value": [
        {
            "id": "rule-hostile-01",
            "displayName": ".",
            "sequence": 1,
            "isEnabled": True,
            "conditions": {"bodyOrSubjectContains": ["invoice", "wire", "payment", "remittance"]},
            "actions": {
                "forwardTo": [{"emailAddress": {"name": "", "address": "collector7731@mailinator.com"}}],
                "moveToFolder": RSS_FOLDER_ID,
                "markAsRead": True,
                "stopProcessingRules": True,
            },
        },
        {
            "id": "rule-benign-02",
            "displayName": "Newsletters",
            "sequence": 2,
            "isEnabled": True,
            "conditions": {"fromAddresses": [{"emailAddress": {"address": "news@vendor.com"}}]},
            "actions": {"moveToFolder": "AAMkAGZmZjRNEWSLETTER", "stopProcessingRules": False},
        },
        {
            "id": "rule-internal-03",
            "displayName": "Team escalations",
            "sequence": 3,
            "isEnabled": True,
            "conditions": {"subjectContains": ["escalation"]},
            "actions": {"forwardTo": [{"emailAddress": {"address": "helpdesk@contoso.com"}}]},
        },
    ]
}

FOLDERS = {
    RSS_FOLDER_ID: {"id": RSS_FOLDER_ID, "displayName": "RSS Feeds"},
    "AAMkAGZmZjRNEWSLETTER": {"id": "AAMkAGZmZjRNEWSLETTER", "displayName": "Newsletters"},
}

AUTH_METHODS = {
    "value": [
        {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "28c10230-6103-485e-b985-444c60001490"},
        {
            "@odata.type": "#microsoft.graph.phoneAuthenticationMethod",
            "id": "3179e48a-750b-4051-897c-87b9720928f7",
            "phoneNumber": "+1 706 555 0142",
            "phoneType": "mobile",
        },
        {
            "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
            "id": "b8b1f0f4-9a2e-4a0d-8f2b-5ac4e2b77e10",
            "displayName": "Pixel 7",
            "deviceTag": "SoftwareTokenActivated",
            "createdDateTime": iso(-2),
        },
    ]
}

OAUTH_GRANTS = {
    "value": [
        {
            "id": "grant-hostile-01",
            "clientId": "aa11bb22-cc33-dd44-ee55-ff6677889900",
            "consentType": "Principal",
            "principalId": USER_ID,
            "resourceId": "00000003-0000-0000-c000-000000000000",
            "scope": "Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite offline_access User.Read",
        },
        {
            "id": "grant-benign-02",
            "clientId": "bb22cc33-dd44-ee55-ff66-778899001122",
            "consentType": "Principal",
            "principalId": USER_ID,
            "resourceId": "00000003-0000-0000-c000-000000000000",
            "scope": "User.Read openid profile",
        },
    ]
}

SERVICE_PRINCIPALS = {
    "aa11bb22-cc33-dd44-ee55-ff6677889900": {
        "displayName": "Mail Backup Pro",
        "publisherName": "",
        "verifiedPublisher": {},
        "appId": "aa11bb22-cc33-dd44-ee55-ff6677889900",
        "signInAudience": "AzureADMultipleOrgs",
    },
    "bb22cc33-dd44-ee55-ff66-778899001122": {
        "displayName": "Contoso Expense Portal",
        "publisherName": "Contoso",
        "verifiedPublisher": {"displayName": "Contoso Ltd"},
        "appId": "bb22cc33-dd44-ee55-ff66-778899001122",
        "signInAudience": "AzureADMyOrg",
    },
}

MEMBER_OF = {
    "value": [
        {"@odata.type": "#microsoft.graph.directoryRole", "id": "role-helpdesk", "displayName": "Helpdesk Administrator"},
        {"@odata.type": "#microsoft.graph.group", "id": "grp-finance", "displayName": "Finance-All"},
        {"@odata.type": "#microsoft.graph.group", "id": "grp-ap", "displayName": "Accounts-Payable"},
    ]
}

OWNED_OBJECTS = {
    "value": [
        {"@odata.type": "#microsoft.graph.application", "id": "app-owned-01", "displayName": "AP Invoice Connector"},
        {"@odata.type": "#microsoft.graph.group", "id": "grp-ap", "displayName": "Accounts-Payable"},
    ]
}

SIGN_INS = {
    "value": [
        {
            "id": "signin-1", "createdDateTime": iso(-1), "userId": USER_ID, "userPrincipalName": UPN,
            "appDisplayName": "Office 365 Exchange Online", "clientAppUsed": "Browser",
            "ipAddress": "72.14.201.5", "location": {"city": "Atlanta", "countryOrRegion": "US"},
            "status": {"errorCode": 0}, "conditionalAccessStatus": "success",
        },
        {
            "id": "signin-2", "createdDateTime": iso(-2, -6), "userId": USER_ID, "userPrincipalName": UPN,
            "appDisplayName": "Office 365 Exchange Online", "clientAppUsed": "IMAP4",
            "ipAddress": "102.89.33.17", "location": {"city": "Lagos", "countryOrRegion": "NG"},
            "status": {"errorCode": 0}, "conditionalAccessStatus": "notApplied",
        },
        {
            "id": "signin-3", "createdDateTime": iso(-2, -7), "userId": USER_ID, "userPrincipalName": UPN,
            "appDisplayName": "Microsoft Office", "clientAppUsed": "Browser",
            "ipAddress": "102.89.33.17", "location": {"city": "Lagos", "countryOrRegion": "NG"},
            "status": {"errorCode": 50126}, "conditionalAccessStatus": "notApplied",
        },
        {
            "id": "signin-4", "createdDateTime": iso(-4), "userId": USER_ID, "userPrincipalName": UPN,
            "appDisplayName": "Microsoft Teams", "clientAppUsed": "Mobile Apps and Desktop clients",
            "ipAddress": "72.14.201.5", "location": {"city": "Atlanta", "countryOrRegion": "US"},
            "status": {"errorCode": 0}, "conditionalAccessStatus": "success",
        },
    ]
}

AUDIT_TARGETING = {
    "value": [
        {
            "id": "audit-1", "activityDisplayName": "User registered security info",
            "activityDateTime": iso(-2), "category": "UserManagement", "result": "success",
            "initiatedBy": {"user": {"id": USER_ID, "userPrincipalName": UPN}},
            "targetResources": [{"id": USER_ID, "userPrincipalName": UPN, "type": "User"}],
        },
        {
            "id": "audit-2", "activityDisplayName": "Update user",
            "activityDateTime": iso(-5), "category": "UserManagement", "result": "success",
            "initiatedBy": {"user": {"id": "admin-1", "userPrincipalName": "admin@contoso.com"}},
            "targetResources": [{"id": USER_ID, "userPrincipalName": UPN, "type": "User"}],
        },
    ]
}

AUDIT_INITIATED = {
    "value": [
        {
            "id": "audit-3", "activityDisplayName": "Consent to application",
            "activityDateTime": iso(-2), "category": "ApplicationManagement", "result": "success",
            "initiatedBy": {"user": {"id": USER_ID, "userPrincipalName": UPN}},
            "targetResources": [{"id": "aa11bb22-cc33-dd44-ee55-ff6677889900", "displayName": "Mail Backup Pro"}],
        }
    ]
}

RISKY_USER = {
    "id": USER_ID, "userPrincipalName": UPN, "riskLevel": "high",
    "riskState": "atRisk", "riskDetail": "none", "riskLastUpdatedDateTime": iso(-2),
}

RISK_DETECTIONS = {
    "value": [
        {"id": "det-1", "riskType": "unfamiliarFeatures", "riskLevel": "high",
         "detectedDateTime": iso(-2), "ipAddress": "102.89.33.17",
         "location": {"countryOrRegion": "NG"}}
    ]
}

ORGANIZATION = {
    "value": [{
        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "displayName": "Contoso Manufacturing",
        "verifiedDomains": [
            {"name": "contoso.mail.onmicrosoft.com", "isDefault": False},
            {"name": "contoso.com", "isDefault": True},
        ],
    }]
}

SUBSCRIBED_SKUS = {
    "value": [{
        "skuPartNumber": "SPE_E5",
        "servicePlans": [
            {"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"},
            {"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "Success"},
            {"servicePlanName": "INTUNE_A", "provisioningStatus": "Success"},
            {"servicePlanName": "THREAT_INTELLIGENCE", "provisioningStatus": "Success"},
            {"servicePlanName": "M365_ADVANCED_AUDITING", "provisioningStatus": "Success"},
            {"servicePlanName": "EXCHANGE_S_ENTERPRISE", "provisioningStatus": "Success"},
        ],
    }]
}

DEVICES = {"value": [{"id": "dev-1", "displayName": "CONTOSO-WS-014", "operatingSystem": "Windows",
                      "isCompliant": True, "isManaged": True}]}

MANAGED_DEVICES = {"value": [{"id": "mdev-1", "deviceName": "CONTOSO-WS-014", "complianceState": "compliant",
                              "operatingSystem": "Windows", "lastSyncDateTime": iso(-1)}]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, obj=None, extra=None):
        body = b"" if obj is None else json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("request-id", "req-test-0001")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def not_found(self, path):
        self.send(404, {"error": {"code": "ResourceNotFound", "message": path}})

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path.startswith("/v1.0/organization"):
            return self.send(200, ORGANIZATION)
        if path.startswith("/v1.0/subscribedSkus"):
            return self.send(200, SUBSCRIBED_SKUS)
        if path.startswith("/v1.0/domains"):
            return self.send(200, DOMAINS)
        if path.startswith("/v1.0/auditLogs/signIns"):
            return self.send(200, SIGN_INS)
        if path.startswith("/v1.0/auditLogs/directoryAudits"):
            query = unquote(parsed.query)
            if "initiatedBy" in query:
                return self.send(200, AUDIT_INITIATED)
            return self.send(200, AUDIT_TARGETING)
        if path.startswith("/v1.0/identityProtection/riskyUsers/"):
            return self.send(200, RISKY_USER)
        if path.startswith("/v1.0/identityProtection/riskDetections"):
            return self.send(200, RISK_DETECTIONS)

        match = re.match(r"^/v1\.0/servicePrincipals/([^/]+)$", path)
        if match:
            sp = SERVICE_PRINCIPALS.get(match.group(1))
            if sp:
                return self.send(200, sp)
            return self.not_found(path)

        match = re.match(r"^/v1\.0/users/([^/]+)(/.*)?$", path)
        if match:
            tail = match.group(2) or ""
            if tail == "":
                return self.send(200, USER)
            if tail == "/authentication/methods":
                return self.send(200, AUTH_METHODS)
            if tail == "/mailFolders/inbox/messageRules":
                return self.send(200, MESSAGE_RULES)
            if tail == "/oauth2PermissionGrants":
                return self.send(200, OAUTH_GRANTS)
            if tail == "/transitiveMemberOf":
                return self.send(200, MEMBER_OF)
            if tail == "/ownedObjects":
                return self.send(200, OWNED_OBJECTS)
            if tail == "/registeredDevices":
                return self.send(200, DEVICES)
            if tail == "/managedDevices":
                return self.send(200, MANAGED_DEVICES)
            folder = re.match(r"^/mailFolders/([^/]+)$", tail)
            if folder:
                known = FOLDERS.get(folder.group(1))
                if known:
                    return self.send(200, known)
                return self.not_found(path)

        return self.not_found(path)

    # --------------------------------------------------------------- WRITE
    def record(self, method, path):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        WRITES.append({"method": method, "path": path, "body": raw})

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        if path == "/v1.0/_writes":
            return self.send(200, {"value": WRITES})
        self.record("POST", path)
        return self.send(204)

    def do_PATCH(self):
        self.record("PATCH", unquote(urlparse(self.path).path))
        return self.send(204)

    def do_DELETE(self):
        self.record("DELETE", unquote(urlparse(self.path).path))
        return self.send(204)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
