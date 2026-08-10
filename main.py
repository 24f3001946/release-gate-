from fastapi import FastAPI

app = FastAPI()


def is_full_sha(ref):
    return (
        isinstance(ref, str)
        and len(ref) == 40
        and all(c in "0123456789abcdef" for c in ref)
    )


@app.post("/release-gate")
def release_gate(data: dict):

    violations = []

    workflow = data["workflow"]
    image = data["image"]

    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if workflow.get("permissions") != required_permissions:
        violations.append("EXCESS_PERMISSION")

    if workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    for action in workflow.get("actions", []):

        owner = action.get("owner")
        ref = action.get("ref", "")

        if owner != "actions":
            if not is_full_sha(ref):
                violations.append("MUTABLE_ACTION")
                break

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is True:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities", 0) > 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    if data.get("target") == "production":

        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if len(violations) == 0 else "block",
        "violations": violations
    }
import re

TENANT_ID = "tenant-b2li6wa"
EMAIL_DOMAIN = "notify-hhi24oa.example"


@app.post("/action-firewall")
def action_firewall(data: dict):

    # 1. Top-level schema
    required = {"provenance", "humanApproved", "action"}
    if set(data.keys()) - {"provenance", "humanApproved", "untrustedContent", "action"}:
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    if not required.issubset(data.keys()):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    action = data.get("action")

    if not isinstance(action, dict):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    tool = action.get("tool")
    args = action.get("args")

    if tool is None or args is None:
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    # 2. Tool allowlist
    allowed_tools = {
        "search",
        "lookup_record",
        "send_email",
        "render_html"
    }

    if tool not in allowed_tools:
        return {"decision": "block", "reason": "TOOL_NOT_ALLOWED"}

    # 3. Tool schemas

    if tool == "search":
        if set(args.keys()) != {"query"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        q = args["query"]

        if not isinstance(q, str) or not (1 <= len(q) <= 200):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "lookup_record":

        if set(args.keys()) != {"tenantId", "recordId"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        if not isinstance(args["recordId"], str) or args["recordId"] == "":
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        # 4. Tenant scope
        if args["tenantId"] != TENANT_ID:
            return {"decision": "block", "reason": "TENANT_SCOPE"}

    elif tool == "send_email":

        if set(args.keys()) != {"to", "subject", "body"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        to = args["to"]

        if not isinstance(to, str) or "@" not in to:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        domain = to.split("@")[-1]

        # 5. Exact email domain
        if domain != EMAIL_DOMAIN:
            return {"decision": "block", "reason": "EGRESS_DENIED"}

        # 6. Human approval
        if data["humanApproved"] is not True:
            return {"decision": "block", "reason": "APPROVAL_REQUIRED"}

    elif tool == "render_html":

        if set(args.keys()) != {"html"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        html = args["html"]

        if not isinstance(html, str):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

        lowered = html.lower()

        if (
            "<script" in lowered
            or "<iframe" in lowered
            or "javascript:" in lowered
            or re.search(r"\son\w+\s*=", lowered)
        ):
            return {"decision": "block", "reason": "UNSAFE_OUTPUT"}

    return {
        "decision": "allow",
        "reason": "ALLOW"
    }

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict, Any

app = FastAPI()

# ---------- Terraform Plan Models ----------

class State(BaseModel):
    backend: str
    locked: bool

class Resource(BaseModel):
    address: str
    type: str
    action: str
    labels: Dict[str, str]
    secret: Optional[str] = None
    forceDestroy: bool

class TerraformPlan(BaseModel):
    environment: str
    state: State
    providerVersion: str
    destroyApproved: bool
    resource: Resource


@app.post("/terraform/plan")
def terraform_plan(plan: TerraformPlan):

    required_labels = {
        "owner": "student-lph2m",
        "environment": "production",
        "cost_center": "cc-4soi"
    }

    # Rule 2
    if plan.environment != "prod-xcwt2n":
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        }

    # Rule 3
    if (
        plan.state.backend not in ["gcs", "s3", "azurerm", "remote"]
        or plan.state.locked is not True
    ):
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        }

    # Rule 4
    allowed_versions = ["6.2.1", "= 6.2.1", "~> 6.0"]
    if plan.providerVersion not in allowed_versions:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        }

    # Rule 5
    for k, v in required_labels.items():
        if plan.resource.labels.get(k) != v:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS"
            }

    # Rule 6
    secret = plan.resource.secret
    if secret is not None:
        if not (isinstance(secret, str) and secret.startswith("secret://") and len(secret) > 9):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            }

    # Rule 7
    stateful = ["storage_bucket", "sql_database", "persistent_disk"]

    if (
        plan.resource.action == "delete"
        and plan.resource.type in stateful
        and not plan.destroyApproved
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        }

    # Rule 8
    if (
        plan.resource.type == "storage_bucket"
        and plan.resource.forceDestroy
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        }

    return {
        "decision": "approve",
        "reason": "APPROVE"
    }
