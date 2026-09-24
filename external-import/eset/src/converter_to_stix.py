"""Builds STIX 2.1 objects from ESET Threat Intelligence v2 REST API payloads."""

from datetime import datetime, timezone
from typing import Optional

import stix2
from dateutil.parser import parse
from pycti import Indicator, Malware, Report, StixCoreRelationship, ThreatActor

# Maps the IOC "type" field ESET's REST API is documented to return onto a
# STIX pattern comparison. If your tenant uses different type labels,
# extend this map -- unmapped IOC types are skipped (and logged) rather
# than guessed at.
IOC_PATTERN_MAP = {
    "domain": "domain-name:value",
    "hostname": "domain-name:value",
    "url": "url:value",
    "ip": "ipv4-addr:value",
    "ipv4": "ipv4-addr:value",
    "ipv6": "ipv6-addr:value",
    "md5": "file:hashes.MD5",
    "sha1": "file:hashes.'SHA-1'",
    "sha256": "file:hashes.'SHA-256'",
}

OBSERVABLE_TYPES_MAP = {
    "domain-name:value": "Domain-Name",
    "url:value": "Url",
    "ipv4-addr:value": "IPv4-Addr",
    "ipv6-addr:value": "IPv6-Addr",
    "file:hashes.MD5": "MD5",
    "file:hashes.'SHA-1'": "SHA-1",
    "file:hashes.'SHA-256'": "SHA-256",
}


def parse_report_date(report: dict) -> datetime:
    raw = (
        report.get("published_at")
        or report.get("date")
        or report.get("created_at")
    )
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return parse(raw)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


class ConverterToStix:
    """Converts ESET report/IOC dicts into STIX2 objects, given an author identity."""

    def __init__(self, helper, author, create_observables: bool = True):
        self.helper = helper
        self.author = author
        self.create_observables = create_observables

    def build_indicator(self, ioc: dict) -> Optional[stix2.Indicator]:
        ioc_type = (ioc.get("type") or "").lower()
        value = ioc.get("value")
        stix_path = IOC_PATTERN_MAP.get(ioc_type)
        if not stix_path or not value:
            self.helper.connector_logger.debug(
                f"Skipping IOC with unmapped/empty type: {ioc}"
            )
            return None

        pattern = f"[{stix_path} = '{value}']"
        indicator_kwargs = dict(
            id=Indicator.generate_id(pattern),
            name=value,
            pattern=pattern,
            pattern_type="stix",
            created_by_ref=self.author["standard_id"],
            valid_from=datetime.now(timezone.utc),
            labels=["eset"],
            object_marking_refs=[stix2.TLP_AMBER.get("id")],
            custom_properties={
                "x_opencti_main_observable_type": OBSERVABLE_TYPES_MAP.get(
                    stix_path
                ),
                "x_opencti_create_observables": self.create_observables,
            },
            allow_custom=True,
        )
        return stix2.Indicator(**indicator_kwargs)

    def build_malware(self, name: str) -> stix2.Malware:
        return stix2.Malware(
            id=Malware.generate_id(name),
            name=name,
            is_family=True,
            created_by_ref=self.author["standard_id"],
            object_marking_refs=[stix2.TLP_AMBER.get("id")],
        )

    def build_threat_actor(self, name: str) -> stix2.ThreatActor:
        return stix2.ThreatActor(
            id=ThreatActor.generate_id(name, "threat-actor"),
            name=name,
            created_by_ref=self.author["standard_id"],
            object_marking_refs=[stix2.TLP_AMBER.get("id")],
        )

    def build_relationship(
        self, relationship_type: str, source_ref: str, target_ref: str
    ) -> stix2.Relationship:
        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=self.author["standard_id"],
            object_marking_refs=[stix2.TLP_AMBER.get("id")],
        )

    def build_report_bundle(self, report: dict, pdf_bytes: Optional[bytes]) -> list:
        """Builds the full STIX object list for one ESET report: the Report
        object itself plus any indicators / malware / threat actors it
        references, with relationships tying them together.
        """
        name = (
            report.get("name")
            or report.get("filename")
            or report.get("title")
            or f"ESET report {report.get('id')}"
        )
        date = parse_report_date(report)
        description = report.get("description") or report.get("summary") or name

        objects = []
        object_refs = [self.author["standard_id"]]

        for ioc in report.get("_iocs", []):
            indicator = self.build_indicator(ioc)
            if indicator is None:
                continue
            objects.append(indicator)
            object_refs.append(indicator.id)

        for malware_name in report.get("malware_families") or report.get(
            "malware", []
        ):
            malware = self.build_malware(malware_name)
            objects.append(malware)
            object_refs.append(malware.id)
            for indicator in [o for o in objects if o.type == "indicator"]:
                objects.append(
                    self.build_relationship(
                        "indicates", indicator.id, malware.id
                    )
                )

        for actor_name in report.get("threat_actors") or []:
            actor = self.build_threat_actor(actor_name)
            objects.append(actor)
            object_refs.append(actor.id)

        files = []
        if pdf_bytes:
            import base64

            files.append(
                {
                    "name": f"{name}.pdf",
                    "data": base64.b64encode(pdf_bytes).decode("utf-8"),
                    "mime_type": "application/pdf",
                    "no_trigger_import": True,
                }
            )

        stix_report = stix2.Report(
            id=Report.generate_id(name, date),
            name=name,
            report_types=[report.get("type", "threat-report")],
            description=description,
            published=date,
            labels=["eset"],
            created_by_ref=self.author["standard_id"],
            object_refs=object_refs,
            object_marking_refs=[stix2.TLP_AMBER.get("id")],
            x_opencti_files=files,
            allow_custom=True,
        )
        objects.append(stix_report)
        return objects
