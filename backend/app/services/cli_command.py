"""Generate provider-specific CLI remediation command hints."""

from __future__ import annotations

_AWS_RESOURCE_COMMANDS: dict[str, str] = {
    "s3_bucket": "aws s3api put-bucket-acl --bucket {resource_id} --acl private",
    "security_group": "aws ec2 describe-security-groups --group-ids {resource_id}",
    "iam_user": "aws iam get-user --user-name {resource_id}",
    "iam_role": "aws iam get-role --role-name {resource_id}",
    "ec2_instance": "aws ec2 describe-instances --instance-ids {resource_id}",
    "rds_instance": "aws rds describe-db-instances --db-instance-identifier {resource_id}",
    "lambda_function": "aws lambda get-function --function-name {resource_id}",
    "kms_key": "aws kms describe-key --key-id {resource_id}",
}

_AZURE_RESOURCE_COMMANDS: dict[str, str] = {
    "virtual_machine": "az vm show --ids {resource_id}",
    "storage_account": "az storage account show --ids {resource_id}",
    "network_security_group": "az network nsg show --ids {resource_id}",
    "key_vault": "az keyvault show --ids {resource_id}",
    "sql_server": "az sql server show --ids {resource_id}",
}

_GCP_RESOURCE_COMMANDS: dict[str, str] = {
    "compute_instance": "gcloud compute instances describe {resource_id}",
    "gcs_bucket": "gsutil iam get gs://{resource_id}",
    "firewall_rule": "gcloud compute firewall-rules describe {resource_id}",
    "gke_cluster": "gcloud container clusters describe {resource_id}",
}

_K8S_RESOURCE_COMMANDS: dict[str, str] = {
    "pod": "kubectl describe pod {resource_id}",
    "deployment": "kubectl describe deployment {resource_id}",
    "service_account": "kubectl describe serviceaccount {resource_id}",
    "cluster_role": "kubectl describe clusterrole {resource_id}",
    "cluster_role_binding": "kubectl describe clusterrolebinding {resource_id}",
    "network_policy": "kubectl describe networkpolicy {resource_id}",
    "ingress": "kubectl describe ingress {resource_id}",
}

_PROVIDER_MAP: dict[str, dict[str, str]] = {
    "aws": _AWS_RESOURCE_COMMANDS,
    "azure": _AZURE_RESOURCE_COMMANDS,
    "gcp": _GCP_RESOURCE_COMMANDS,
    "k8s": _K8S_RESOURCE_COMMANDS,
}

_PROVIDER_FALLBACK: dict[str, str] = {
    "aws": "aws {resource_type} describe --ids {resource_id}",
    "azure": "az {resource_type} show --ids {resource_id}",
    "gcp": "gcloud {resource_type} describe {resource_id}",
    "k8s": "kubectl describe {resource_type} {resource_id}",
}


def build_cli_command(
    provider: str,
    resource_type: str,
    resource_id: str,
    remediation_code: str | None = None,
) -> str | None:
    """Return the best available CLI command for a finding.

    Priority:
    1. remediation_code stored on the Finding (from Prowler)
    2. Known resource-type template for the provider
    3. Provider-level fallback template
    4. None if provider is unknown
    """
    if remediation_code:
        return remediation_code

    templates = _PROVIDER_MAP.get(provider)
    if templates:
        template = templates.get(resource_type) or _PROVIDER_FALLBACK.get(provider)
        if template:
            safe_resource_id = resource_id.split("/")[-1].split(":")[-1]
            return template.format(
                resource_id=safe_resource_id,
                resource_type=resource_type.replace("_", "-"),
            )

    return None
