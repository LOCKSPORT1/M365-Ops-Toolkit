import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

state = {"users_hits": 0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, code, obj=None, extra=None):
        body = b"" if obj is None else json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("request-id", "req-9f2")
        self.send_header("client-request-id", "cli-771")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/v1.0/users"):
            state["users_hits"] += 1
            n = state["users_hits"]
            if n == 1:
                return self.send(429, {"error": {"code": "TooManyRequests", "message": "throttled"}}, {"Retry-After": "1"})
            if n == 2:
                return self.send(200, {"value": [{"id": "u1"}, {"id": "u2"}],
                                       "@odata.nextLink": "http://127.0.0.1:8099/v1.0/users?$skiptoken=X"})
            return self.send(200, {"value": [{"id": "u3"}]})
        if self.path.startswith("/v1.0/directoryRoles"):
            return self.send(403, {"error": {"code": "Authorization_RequestDenied",
                                             "message": "Insufficient privileges to complete the operation."}})
        if self.path.startswith("/v1.0/organization"):
            return self.send(200, {"value": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                                              "displayName": "Contoso Manufacturing",
                                              "verifiedDomains": [{"name": "contoso.mail.onmicrosoft.com", "isDefault": False},
                                                                  {"name": "contoso.com", "isDefault": True}]}]})
        if self.path.startswith("/v1.0/subscribedSkus"):
            return self.send(200, {"value": [
                {"skuPartNumber": "SPE_E5", "servicePlans": [
                    {"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"},
                    {"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "Success"},
                    {"servicePlanName": "INTUNE_A", "provisioningStatus": "Success"},
                    {"servicePlanName": "THREAT_INTELLIGENCE", "provisioningStatus": "Success"},
                    {"servicePlanName": "M365_ADVANCED_AUDITING", "provisioningStatus": "Success"},
                    {"servicePlanName": "EXCHANGE_S_ENTERPRISE", "provisioningStatus": "Success"},
                    {"servicePlanName": "ADALLOM_S_O365", "provisioningStatus": "Disabled"}]}]})
        return self.send(404, {"error": {"code": "ResourceNotFound", "message": self.path}})

    def do_POST(self):
        return self.send(204)

HTTPServer(("127.0.0.1", 8099), H).serve_forever()
