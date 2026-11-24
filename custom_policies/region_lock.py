from typing import Dict, List, Any
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.provider.base_check import BaseProviderCheck


class AWSApprovedRegionLock(BaseProviderCheck):
    def __init__(self) -> None:
        name = "Ensure AWS provider is locked to approved data-residency region (ap-southeast-2)"
        id = "CKV_CUSTOM_1"
        supported_provider = ["aws"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_provider=supported_provider,
        )

    def scan_provider_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        approved_regions = ["ap-southeast-2"]
        region = conf.get("region")

        if isinstance(region, list) and len(region) > 0:
            if region[0] in approved_regions:
                return CheckResult.PASSED
        elif isinstance(region, str) and region in approved_regions:
            return CheckResult.PASSED

        return CheckResult.FAILED


check = AWSApprovedRegionLock()