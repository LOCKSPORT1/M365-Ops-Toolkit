"""
Azure Resource Manager test double for MtAzurePosture.

Stages a small but deliberately imperfect estate:

  - NSG rule allowing Internet inbound on 3389 (attached, so Critical)
  - NSG rule with a 1000-4000 port range that swallows 1433, on an unattached NSG
  - storage account with public blob access, HTTP allowed, TLS 1.0, open firewall
  - a clean storage account, to prove the rules do not fire on everything
  - a VM with no backup, and one protected by a Recovery Services vault
  - an unattached disk, an orphaned public IP, an orphaned NIC
  - two user principals holding Owner at subscription scope, plus a classic admin
  - an alert rule with no action group, an action group with no receivers
  - a Log Analytics workspace at 30 day retention
  - Policy Insights returns 403, to exercise the coverage-gap path

    python3 Start-FakeArm.py       # listens on 127.0.0.1:8098
"""

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlparse

PORT = 8098
SUB = "11111111-2222-3333-4444-555555555555"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-prod"

SUBSCRIPTIONS = {"value": [
    {"subscriptionId": SUB, "displayName": "Contoso Production", "state": "Enabled",
     "tenantId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
]}

ROLE_DEFS = {"value": [
    {"id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
     "properties": {"roleName": "Owner"}},
    {"id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/contrib-guid",
     "properties": {"roleName": "Contributor"}},
]}

ROLE_ASSIGNMENTS = {"value": [
    {"id": "ra-1", "properties": {
        "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
        "principalId": "user-1", "principalType": "User", "scope": f"/subscriptions/{SUB}",
        "createdOn": "2024-03-11T00:00:00Z"}},
    {"id": "ra-2", "properties": {
        "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
        "principalId": "user-2", "principalType": "User", "scope": f"/subscriptions/{SUB}",
        "createdOn": "2023-08-02T00:00:00Z"}},
    {"id": "ra-3", "properties": {
        "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/contrib-guid",
        "principalId": "grp-eng", "principalType": "Group", "scope": f"/subscriptions/{SUB}",
        "createdOn": "2024-01-15T00:00:00Z"}},
]}

CLASSIC_ADMINS = {"value": [
    {"id": "ca-1", "properties": {"emailAddress": "legacy@contoso.com", "role": "ServiceAdministrator"}}
]}

NSGS = {"value": [
    {"name": "nsg-web", "id": f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
     "properties": {
         "subnets": [{"id": f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/web"}],
         "networkInterfaces": [],
         "securityRules": [
             {"name": "allow-rdp-any", "properties": {
                 "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "priority": 100,
                 "sourceAddressPrefix": "Internet", "destinationPortRange": "3389"}},
             {"name": "allow-https", "properties": {
                 "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "priority": 110,
                 "sourceAddressPrefix": "Internet", "destinationPortRange": "443"}},
             {"name": "deny-all", "properties": {
                 "direction": "Inbound", "access": "Deny", "protocol": "*", "priority": 4096,
                 "sourceAddressPrefix": "*", "destinationPortRange": "*"}},
         ]}},
    {"name": "nsg-orphan", "id": f"{RG}/providers/Microsoft.Network/networkSecurityGroups/nsg-orphan",
     "properties": {
         "subnets": [], "networkInterfaces": [],
         "securityRules": [
             {"name": "allow-range", "properties": {
                 "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "priority": 200,
                 "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "1000-4000"}},
         ]}},
]}

PUBLIC_IPS = {"value": [
    {"name": "pip-gw", "id": f"{RG}/providers/Microsoft.Network/publicIPAddresses/pip-gw",
     "sku": {"name": "Standard"},
     "properties": {"ipConfiguration": {"id": f"{RG}/providers/Microsoft.Network/virtualNetworkGateways/vgw-prod"}}},
    {"name": "pip-orphan", "id": f"{RG}/providers/Microsoft.Network/publicIPAddresses/pip-orphan",
     "sku": {"name": "Standard"}, "properties": {}},
]}

NICS = {"value": [
    {"name": "nic-app01", "id": f"{RG}/providers/Microsoft.Network/networkInterfaces/nic-app01",
     "properties": {"virtualMachine": {"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-app01"}}},
    {"name": "nic-stale", "id": f"{RG}/providers/Microsoft.Network/networkInterfaces/nic-stale",
     "properties": {}},
]}

STORAGE = {"value": [
    {"name": "stlegacydata", "id": f"{RG}/providers/Microsoft.Storage/storageAccounts/stlegacydata",
     "location": "eastus",
     "properties": {"allowBlobPublicAccess": True, "supportsHttpsTrafficOnly": False,
                    "minimumTlsVersion": "TLS1_0", "allowSharedKeyAccess": True,
                    "networkAcls": {"defaultAction": "Allow"}}},
    {"name": "stappsecure", "id": f"{RG}/providers/Microsoft.Storage/storageAccounts/stappsecure",
     "location": "eastus",
     "properties": {"allowBlobPublicAccess": False, "supportsHttpsTrafficOnly": True,
                    "minimumTlsVersion": "TLS1_2", "allowSharedKeyAccess": False,
                    "networkAcls": {"defaultAction": "Deny"}}},
]}

VMS = {"value": [
    {"name": "vm-app01", "id": f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-app01", "location": "eastus"},
    {"name": "vm-sql01", "id": f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-sql01", "location": "eastus"},
]}

DISKS = {"value": [
    {"name": "vm-app01_OsDisk", "id": f"{RG}/providers/Microsoft.Compute/disks/vm-app01_OsDisk",
     "properties": {"diskState": "Attached", "diskSizeGB": 128}},
    {"name": "orphan-datadisk", "id": f"{RG}/providers/Microsoft.Compute/disks/orphan-datadisk",
     "properties": {"diskState": "Unattached", "diskSizeGB": 512}},
]}

VAULTS = {"value": [
    {"name": "rsv-prod", "id": f"{RG}/providers/Microsoft.RecoveryServices/vaults/rsv-prod"}
]}

PROTECTED_ITEMS = {"value": [
    {"name": "pi-1", "properties": {
        "sourceResourceId": f"{RG}/providers/Microsoft.Compute/virtualMachines/vm-app01",
        "protectionState": "Protected"}}
]}

POLICY_ASSIGNMENTS = {"value": [
    {"name": "require-tags", "id": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/require-tags",
     "properties": {"displayName": "Require cost centre tag"}}
]}

WORKSPACES = {"value": [
    {"name": "law-prod", "id": f"{RG}/providers/Microsoft.OperationalInsights/workspaces/law-prod",
     "properties": {"retentionInDays": 30, "sku": {"name": "PerGB2018"}}}
]}

ALERTS = {"value": [
    {"name": "cpu-high", "id": f"{RG}/providers/Microsoft.Insights/metricAlerts/cpu-high",
     "properties": {"enabled": True, "actions": [{"actionGroupId": "ag-oncall"}]}},
    {"name": "disk-low", "id": f"{RG}/providers/Microsoft.Insights/metricAlerts/disk-low",
     "properties": {"enabled": True, "actions": []}},
]}

ACTION_GROUPS = {"value": [
    {"name": "ag-oncall", "id": f"{RG}/providers/Microsoft.Insights/actionGroups/ag-oncall",
     "properties": {"enabled": True, "emailReceivers": [{"name": "oncall", "emailAddress": "oncall@contoso.com"}]}},
    {"name": "ag-empty", "id": f"{RG}/providers/Microsoft.Insights/actionGroups/ag-empty",
     "properties": {"enabled": True, "emailReceivers": [], "smsReceivers": [], "webhookReceivers": []}},
]}

READS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, code, obj=None):
        body = b"" if obj is None else json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("request-id", "arm-test-0001")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        if path == "/_reads":
            return self.send(200, {"value": READS})
        # Policy Insights summarize is a POST in real ARM; deny it here to
        # exercise the coverage-gap path a plain Contributor actually hits.
        return self.send(403, {"error": {"code": "AuthorizationFailed",
                                         "message": "does not have authorization to perform action"}})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        READS.append(path)

        if path == "/subscriptions":
            return self.send(200, SUBSCRIPTIONS)

        if "/providers/Microsoft.PolicyInsights/" in path:
            return self.send(403, {"error": {"code": "AuthorizationFailed",
                                             "message": "The client does not have authorization to perform action "
                                                        "'Microsoft.PolicyInsights/policyStates/read'."}})

        table = [
            (r"/providers/Microsoft\.Authorization/roleAssignments$", ROLE_ASSIGNMENTS),
            (r"/providers/Microsoft\.Authorization/roleDefinitions$", ROLE_DEFS),
            (r"/providers/Microsoft\.Authorization/classicAdministrators$", CLASSIC_ADMINS),
            (r"/providers/Microsoft\.Authorization/policyAssignments$", POLICY_ASSIGNMENTS),
            (r"/providers/Microsoft\.Network/networkSecurityGroups$", NSGS),
            (r"/providers/Microsoft\.Network/publicIPAddresses$", PUBLIC_IPS),
            (r"/providers/Microsoft\.Network/networkInterfaces$", NICS),
            (r"/providers/Microsoft\.Storage/storageAccounts$", STORAGE),
            (r"/providers/Microsoft\.Compute/virtualMachines$", VMS),
            (r"/providers/Microsoft\.Compute/disks$", DISKS),
            (r"/providers/Microsoft\.RecoveryServices/vaults$", VAULTS),
            (r"/backupProtectedItems$", PROTECTED_ITEMS),
            (r"/providers/Microsoft\.OperationalInsights/workspaces$", WORKSPACES),
            (r"/providers/Microsoft\.Insights/metricAlerts$", ALERTS),
            (r"/providers/Microsoft\.Insights/actionGroups$", ACTION_GROUPS),
        ]

        for pattern, payload in table:
            if re.search(pattern, path):
                return self.send(200, payload)

        return self.send(404, {"error": {"code": "ResourceNotFound", "message": path}})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
