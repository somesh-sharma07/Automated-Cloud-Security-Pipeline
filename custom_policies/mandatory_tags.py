from typing import Dict, List, Any
from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class MandatoryGovernanceTags(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure core AWS network resources enforce mandatory Owner and Environment tags"
        id = "CKV_CUSTOM_2"
        supported_resources = [
            "aws_vpc",
            "aws_subnet",
            "aws_security_group",
            "aws_internet_gateway",
            "aws_route_table",
        ]
        categories = [CheckCategories.CONVENTION]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        required_tags = ["Owner", "Environment"]
        tags_block = conf.get("tags")

        if not tags_block:
            return CheckResult.FAILED

        tags = tags_block[0] if isinstance(tags_block, list) else tags_block
        if not isinstance(tags, dict):
            return CheckResult.FAILED

        for tag in required_tags:
            if tag not in tags or not str(tags[tag]).strip():
                return CheckResult.FAILED

        return CheckResult.PASSED


check = MandatoryGovernanceTags()