from google.cloud import storage
from google.api_core.exceptions import Forbidden
import yaml

# =========================
# Configuration
# =========================

PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}

SENSITIVE_ROLES = {
    "roles/storage.admin",
    "roles/storage.objectAdmin",
}

try:
    with open("config.yaml") as f:
        config = yaml.safe_load(f) or {}
except FileNotFoundError:
    print("config.yaml not found. Create yaml file or remove IAM allowlist checks.")
    sys.exit(1)

ALLOWED_SERVICE_ACCOUNTS = {
    f"serviceAccount:{sa}"
    for sa in config.get("allowed_service_accounts", [])
}


# =========================
# IAM Checks
# =========================

def run_iam_checks(bucket):
    findings = []

    try:
        policy = bucket.get_iam_policy(requested_policy_version=3)
    except Forbidden:
        findings.append({
            "bucket": bucket.name,
            "issue": "Insufficient permissions to read IAM policy",
            "risk": "INFO",
        })
        return findings

    for binding in policy.bindings:
        members = set(binding["members"])
        role = binding["role"]

        # Public access
        public = PUBLIC_PRINCIPALS.intersection(members)
        if public:
            findings.append({
                "bucket": bucket.name,
                "issue": "Public IAM access",
                "members": list(public),
                "role": role,
                "risk": "HIGH",
            })

        # Over-privileged service account
        if role in SENSITIVE_ROLES:
            for m in members:
                if m.startswith("serviceAccount:"):
                    findings.append({
                        "bucket": bucket.name,
                        "issue": "Over-privileged service account",
                        "member": m,
                        "role": role,
                        "risk": "MEDIUM",
                    })

        # Unexpected service account
        for m in members:
            if m.startswith("serviceAccount:") and m != ALLOWED_SERVICE_ACCOUNT:
                findings.append({
                    "bucket": bucket.name,
                    "issue": "Unexpected service account",
                    "member": m,
                    "risk": "HIGH",
                })

        # Human access
        for m in members:
            if m.startswith("user:"):
                findings.append({
                    "bucket": bucket.name,
                    "issue": "Human IAM access",
                    "member": m,
                    "role": role,
                    "risk": "LOW",
                })

    return findings

# =========================
# Bucket Configuration Checks
# =========================

def run_bucket_checks(bucket):
    findings = []

    if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
        findings.append({
            "bucket": bucket.name,
            "issue": "Uniform bucket-level access disabled",
            "risk": "MEDIUM",
        })

    if bucket.iam_configuration.public_access_prevention != "enforced":
        findings.append({
            "bucket": bucket.name,
            "issue": "Public access prevention not enforced",
            "risk": "MEDIUM",
        })

    return findings

# =========================
# Output
# =========================

def print_findings(findings):
    if not findings:
        print("No IAM or bucket security issues detected")
        return

    print("Bucket security findings:")
    for f in findings:
        print(
            f"- [{f.get('risk', 'INFO')}] "
            f"{f['bucket']}: {f['issue']}"
        )

# =========================
# Entry Point
# =========================

def main():
    client = storage.Client()
    findings = []

    for bucket in client.list_buckets():
        findings.extend(run_iam_checks(bucket))
        findings.extend(run_bucket_checks(bucket))

    print_findings(findings)

if __name__ == "__main__":
    main()
