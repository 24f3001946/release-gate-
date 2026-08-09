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
