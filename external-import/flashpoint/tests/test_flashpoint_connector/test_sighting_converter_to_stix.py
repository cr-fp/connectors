from unittest.mock import Mock

import stix2
from connectors_sdk.models import AttackPattern, Indicator, Malware, Organization, Relationship
from connectors_sdk.models.enums import RelationshipType
from flashpoint_connector.sighting_converter_to_stix import SightingConverterToStix


def _build_converter() -> SightingConverterToStix:
    helper = Mock()
    helper.connector_logger = Mock()
    return SightingConverterToStix(helper=helper)


def test_convert_sightings_page_to_stix_deduplicates_indicators_per_page():
    converter = _build_converter()
    sightings_page = [
        {
            "id": "s-1",
            "href": "https://app.flashpoint.io/s-1",
            "source": "flashpoint_detection",
            "sighted_at": "2026-03-06T11:30:00Z",
            "created_at": "2026-03-06T11:35:00Z",
            "modified_at": "2026-03-06T11:40:00Z",
            "description": "First sighting",
            "tags": ["actor:apt-one", "malware:cobaltstrike"],
            "mitre_attack_ids": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                }
            ],
            "related_iocs": [
                {
                    "id": "ioc-shared",
                    "type": "domain",
                    "value": "example.org",
                    "href": "https://app.flashpoint.io/ioc-shared",
                    "score": {"value": "malicious", "last_scored_at": None},
                    "last_seen_at": "2026-03-06T11:30:00Z",
                },
                {
                    "id": "ioc-unique",
                    "type": "ipv4",
                    "value": "198.51.100.42",
                    "href": "https://app.flashpoint.io/ioc-unique",
                    "score": {"value": "suspicious", "last_scored_at": None},
                    "last_seen_at": "2026-03-06T11:31:00Z",
                },
            ],
        },
        {
            "id": "s-2",
            "href": "https://app.flashpoint.io/s-2",
            "source": "flashpoint_extraction",
            "sighted_at": "2026-03-06T12:30:00Z",
            "created_at": "2026-03-06T12:35:00Z",
            "modified_at": "2026-03-06T12:40:00Z",
            "description": "Second sighting",
            "tags": ["actor:apt-two"],
            "related_iocs": [
                {
                    "id": "ioc-shared",
                    "type": "domain",
                    "value": "example.org",
                    "href": "https://app.flashpoint.io/ioc-shared",
                    "score": {"value": "malicious", "last_scored_at": None},
                    "last_seen_at": "2026-03-06T12:30:00Z",
                }
            ],
        },
    ]

    octi_objects = converter.convert_sightings_page_to_stix(sightings_page)

    indicators = [obj for obj in octi_objects if isinstance(obj, Indicator)]
    organizations = [obj for obj in octi_objects if isinstance(obj, Organization)]
    sightings = [obj for obj in octi_objects if isinstance(obj, stix2.Sighting)]
    groupings = [obj for obj in octi_objects if isinstance(obj, stix2.Grouping)]

    assert len(indicators) == 2
    assert sorted(indicator.name for indicator in indicators) == [
        "198.51.100.42",
        "example.org",
    ]
    assert len(organizations) == 2
    assert len(sightings) == 3
    assert len(groupings) == 2


def test_convert_sightings_page_to_stix_grouping_refs_include_indicator_and_observable_ids():
    converter = _build_converter()
    sighting = {
        "id": "s-1",
        "href": "https://app.flashpoint.io/s-1",
        "source": "flashpoint_detection",
        "sighted_at": "2026-03-06T11:30:00Z",
        "created_at": "2026-03-06T11:35:00Z",
        "modified_at": "2026-03-06T11:40:00Z",
        "description": "First sighting",
        "tags": ["malware:cobaltstrike"],
        "related_iocs": [
            {
                "id": "ioc-domain",
                "type": "domain",
                "value": "example.org",
                "href": "https://app.flashpoint.io/ioc-domain",
                "score": {"value": "malicious", "last_scored_at": None},
                "last_seen_at": "2026-03-06T11:30:00Z",
            },
            {
                "id": "ioc-ip",
                "type": "ipv4",
                "value": "198.51.100.42",
                "href": "https://app.flashpoint.io/ioc-ip",
                "score": {"value": "suspicious", "last_scored_at": None},
                "last_seen_at": "2026-03-06T11:31:00Z",
            },
        ],
    }

    octi_objects = converter.convert_sightings_page_to_stix([sighting])

    indicators = [obj for obj in octi_objects if isinstance(obj, Indicator)]
    non_indicator_ids = {
        obj.id
        for obj in octi_objects
        if hasattr(obj, "id") and not isinstance(obj, Indicator)
    }
    grouping = next(obj for obj in octi_objects if isinstance(obj, stix2.Grouping))

    indicator_ids = {indicator.id for indicator in indicators}
    assert indicator_ids.issubset(set(grouping.object_refs))
    assert any(object_id in grouping.object_refs for object_id in non_indicator_ids)


def test_convert_sightings_page_to_stix_builds_mitre_and_tag_context():
    converter = _build_converter()
    sighting = {
        "id": "s-ctx-1",
        "href": "https://app.flashpoint.io/s-ctx-1",
        "source": "flashpoint_detection",
        "sighted_at": "2026-03-06T11:30:00Z",
        "created_at": "2026-03-06T11:35:00Z",
        "modified_at": "2026-03-06T11:40:00Z",
        "description": "Context sighting",
        "tags": ["actor:apt-one", "malware:cobaltstrike"],
        "mitre_attack_ids": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            }
        ],
        "related_iocs": [
            {
                "id": "ioc-domain",
                "type": "domain",
                "value": "example.org",
                "href": "https://app.flashpoint.io/ioc-domain",
                "score": {"value": "malicious", "last_scored_at": None},
                "last_seen_at": "2026-03-06T11:30:00Z",
            }
        ],
    }

    octi_objects = converter.convert_sightings_page_to_stix([sighting])

    assert any(isinstance(obj, AttackPattern) for obj in octi_objects)
    assert any(isinstance(obj, Malware) and obj.name == "cobaltstrike" for obj in octi_objects)
    assert any(
        isinstance(obj, Relationship) and obj.type == RelationshipType.INDICATES
        for obj in octi_objects
    )


def test_convert_sightings_page_to_stix_skips_invalid_related_iocs():
    converter = _build_converter()
    sighting = {
        "id": "s-invalid-1",
        "href": "https://app.flashpoint.io/s-invalid-1",
        "source": "flashpoint_detection",
        "sighted_at": "2026-03-06T11:30:00Z",
        "created_at": "2026-03-06T11:35:00Z",
        "modified_at": "2026-03-06T11:40:00Z",
        "description": "Invalid IOC sighting",
        "tags": [],
        "related_iocs": [
            {
                "id": "ioc-invalid",
                "type": "domain",
                "value": "not a domain",
                "href": "https://app.flashpoint.io/ioc-invalid",
                "score": {"value": "malicious", "last_scored_at": None},
                "last_seen_at": "2026-03-06T11:30:00Z",
            }
        ],
    }

    octi_objects = converter.convert_sightings_page_to_stix([sighting])

    assert octi_objects == []
