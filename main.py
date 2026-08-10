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

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Literal

# ---------- Validation Error Handler ----------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=200,
        content={
            "decision": "reject",
            "reason": "INVALID_PLAN"
        }
    )

# ---------- Terraform Plan Models ----------

class State(BaseModel):
    backend: str
    locked: bool

class Resource(BaseModel):
    address: str
    type: str
    action: Literal["create", "update", "delete"]
    labels: Dict[str, str]
    secret: Optional[str] = None
    forceDestroy: bool

class TerraformPlan(BaseModel):
    environment: str
    state: State
    providerVersion: str
    destroyApproved: bool
    resource: Resource

# ---------- Terraform Endpoint ----------

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
        if not (
            isinstance(secret, str)
            and secret.startswith("secret://")
            and len(secret) > len("secret://")
        ):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            }

    # Rule 7
    stateful_resources = [
        "storage_bucket",
        "sql_database",
        "persistent_disk"
    ]

    if (
        plan.resource.action == "delete"
        and plan.resource.type in stateful_resources
        and not plan.destroyApproved
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED"
        }

    # Rule 8
    if (
        plan.environment == "prod-xcwt2n"
        and plan.resource.type == "storage_bucket"
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

from fastapi import Request
from urllib.parse import urlparse, unquote
import html
import re

ALLOWED_HOSTS = {
    "cdn-dob37yx.example",
    "app-lhr6olf.example"
}

# -------------------------
# URL Extraction
# -------------------------

def extract_urls(channel, text):
    urls = []

    if channel == "html":
        urls += re.findall(
            r'''(?:href|src)\s*=\s*["']([^"']+)["']''',
            text,
            re.I
        )

    elif channel == "markdown":
        urls += re.findall(
            r'\]\(([^)]+)\)',
            text
        )

    elif channel == "url":
        urls.append(text.strip())

    return urls


# -------------------------
# Dangerous Scheme
# -------------------------

def dangerous_scheme(text):
    return bool(
        re.search(
            r'(javascript|data|vbscript)\s*:',
            text,
            re.I
        )
    )


# -------------------------
# External Exfil Check
# -------------------------

def external_exfil(channel, text):
    urls = extract_urls(channel, text)

    for u in urls:
        u = u.strip()

        # protocol-relative URL
        if u.startswith("//"):
            u = "https:" + u

        # relative URL allowed
        elif u.startswith("/"):
            continue

        parsed = urlparse(u)

        # explicit scheme not http/https
        if parsed.scheme and parsed.scheme.lower() not in ["http", "https"]:
            return "DANGEROUS_SCHEME"

        if parsed.hostname:
            if parsed.hostname not in ALLOWED_HOSTS:
                return "EXTERNAL_EXFIL"

    return None


# -------------------------
# Channel Evaluation
# -------------------------

def evaluate(channel, text):

    if channel == "html":

        if re.search(
            r'<\s*(script|iframe|object|embed)\b',
            text,
            re.I
        ):
            return "SCRIPT_TAG"

        if re.search(
            r'\bon[a-z0-9_]+\s*=',
            text,
            re.I
        ):
            return "EVENT_HANDLER"

        if dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        result = external_exfil(channel, text)
        if result:
            return result

    elif channel in ["markdown", "url"]:

        if dangerous_scheme(text):
            return "DANGEROUS_SCHEME"

        result = external_exfil(channel, text)
        if result:
            return result

    elif channel == "sql":

        if re.search(
            r"('|\"|;|--|/\*|\bunion\b|or\s+1\s*=\s*1)",
            text,
            re.I
        ):
            return "SQL_METACHAR"

    elif channel == "shell":

        if re.search(
            r"(;|&|\||`|<|>|\$\(|\$\{)",
            text
        ):
            return "SHELL_METACHAR"

    return "SAFE"


# -------------------------
# Endpoint
# -------------------------

from fastapi import Request

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    try:
        body = await request.json()
    except Exception:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(body, dict):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if "channel" not in body or "output" not in body:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    channel = body.get("channel")
    output = body.get("output")

    if not isinstance(channel, str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if not isinstance(output, str):
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if channel not in ["html", "markdown", "url", "sql", "shell"]:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    if len(output) > 20000:
        return {
            "safe": False,
            "reason": "INVALID_SCHEMA"
        }

    # KEEP all your existing logic below
    # encoded payload check
    # evaluate(channel, output)
    # SAFE response
    # -------------------------
    # Rule 2: ENCODED_PAYLOAD
    # -------------------------

    decoded = unquote(output)
    decoded = html.unescape(decoded)

    try:
        decoded = decoded.encode().decode("unicode_escape")
    except Exception:
        pass

    if decoded != output:
        if evaluate(channel, decoded) != "SAFE":
            return {
                "safe": False,
                "reason": "ENCODED_PAYLOAD"
            }

    # -------------------------
    # Rule 3+
    # -------------------------

    result = evaluate(channel, output)

    if result == "SAFE":
        return {
            "safe": True,
            "reason": "SAFE"
        }

    return {
        "safe": False,
        "reason": result
    }

from fastapi import Request
from datetime import datetime, timezone

VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

def parse_ts(ts):
    try:
        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )
    except:
        return None


@app.post("/corroborate")
async def corroborate(request: Request):

    # Rule 1: invalid
    try:
        body = await request.json()
    except:
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    if not isinstance(body, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    claim = body.get("claim")
    as_of = body.get("asOf")
    staleness = body.get("stalenessDays")
    sources = body.get("sources")

    if not isinstance(claim, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    if not isinstance(claim.get("value"), str):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    if not isinstance(sources, list):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    if not isinstance(staleness, (int, float)):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    as_of_dt = parse_ts(as_of)
    if as_of_dt is None:
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    claim_value = claim["value"]

    fresh_valid = []

    for s in sources:

        if not isinstance(s, dict):
            continue

        if s.get("type") not in VALID_TYPES:
            continue

        if not all(
            isinstance(s.get(k), str)
            for k in ["id", "origin", "value", "observedAt"]
        ):
            continue

        observed = parse_ts(s["observedAt"])
        if observed is None:
            continue

        age_days = (
            as_of_dt - observed
        ).total_seconds() / 86400

        if age_days < 0:
            continue

        if age_days > staleness:
            continue

        fresh_valid.append(s)

    # Rule 2: contradicted
    contradicting = sorted(
        s["id"]
        for s in fresh_valid
        if s.get("authoritative") is True
        and s["value"] != claim_value
    )

    if contradicting:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": contradicting
        }

    # Rule 3: supported
    matching = [
        s for s in fresh_valid
        if s["value"] == claim_value
    ]

    by_origin = {}

    for s in matching:
        origin = s["origin"]

        if (
            origin not in by_origin
            or s["id"] < by_origin[origin]["id"]
        ):
            by_origin[origin] = s

    reps = list(by_origin.values())

    if len(reps) >= 2:

        ids = sorted(
            r["id"]
            for r in reps
        )

        types = {
            r["type"]
            for r in reps
        }

        confidence = (
            "high"
            if len(types) >= 2
            else "medium"
        )

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": ids
        }

    # Rule 4
    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }
