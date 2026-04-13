from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

import stix2
from connectors_sdk.models import (
    AttackPattern,
    ExternalReference,
    Indicator,
    IntrusionSet,
    KillChainPhase,
    Malware,
    Organization,
    Reference,
    Relationship,
)
from connectors_sdk.models.enums import RelationshipType
from pycti import Grouping as PyctiGrouping

from .indicator_converter_to_stix import IndicatorConverterToStix
from .utils import is_domain


class SightingConverterToStix(IndicatorConverterToStix):
    def _build_related_ioc_external_references(
        self, related_ioc: dict
    ) -> list[ExternalReference]:
        external_references = []

        reference_url = related_ioc.get("href")
        if reference_url:
            external_references.append(
                ExternalReference(source_name="Flashpoint", url=reference_url)
            )

        flashpoint_indicator_id = related_ioc.get("id")
        if flashpoint_indicator_id:
            external_references.append(
                ExternalReference(
                    source_name="Flashpoint",
                    external_id=str(flashpoint_indicator_id),
                )
            )

        return external_references

    def _build_sighting_external_references(self, sighting: dict) -> list[ExternalReference]:
        external_references = []

        sighting_href = sighting.get("href")
        if sighting_href:
            external_references.append(
                ExternalReference(source_name="Flashpoint", url=sighting_href)
            )

        sighting_id = sighting.get("id")
        if sighting_id:
            external_references.append(
                ExternalReference(
                    source_name="Flashpoint",
                    external_id=f"sighting:{sighting_id}",
                )
            )

        return external_references

    def _extract_sighting_tags(self, sighting: dict) -> list[str]:
        return self._normalize_labels(sighting.get("tags") or [])

    def _extract_entities_from_sighting_tags(
        self, sighting: dict
    ) -> tuple[list[str], list[str]]:
        actor_names = set()
        malware_names = set()

        for tag in self._extract_sighting_tags(sighting):
            if tag.startswith("actor:"):
                actor_name = tag[len("actor:") :].strip()
                if actor_name:
                    actor_names.add(actor_name)
            elif tag.startswith("malware:"):
                malware_name = tag[len("malware:") :].strip()
                if malware_name:
                    malware_names.add(malware_name)

        return sorted(actor_names), sorted(malware_names)

    def _normalize_related_ioc(
        self, related_ioc: dict, fallback_seen_at: datetime | None
    ) -> dict | None:
        ioc_type = self._extract_ioc_type(related_ioc)
        if ioc_type is None:
            return None

        forced_file_stix_path = None
        if ioc_type.lower() == "file":
            file_ioc = self._extract_file_ioc(related_ioc)
            if file_ioc is not None:
                forced_file_stix_path, ioc_value = file_ioc
            else:
                ioc_value = self._extract_ioc_value(related_ioc, ioc_type)
        else:
            ioc_value = self._extract_ioc_value(related_ioc, ioc_type)

        if ioc_value is None:
            return None

        observable_definition = self._resolve_observable_definition(ioc_type)
        if observable_definition is None:
            return None

        stix_type, stix_path, opencti_main_observable_type = observable_definition
        if stix_type == "file" and forced_file_stix_path:
            stix_path = forced_file_stix_path

        if stix_type == "domain-name" and not is_domain(ioc_value):
            self.helper.connector_logger.warning(
                "Skipping related indicator with invalid domain value",
                {"ioc_value": ioc_value},
            )
            return None

        pattern = self._build_pattern(stix_type, stix_path, ioc_value)
        if pattern is None:
            return None

        last_seen = self._parse_datetime(related_ioc.get("last_seen_at"))
        valid_from = last_seen or fallback_seen_at or datetime.now(timezone.utc)

        return {
            "pattern": pattern,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "stix_type": stix_type,
            "stix_path": stix_path,
            "opencti_main_observable_type": opencti_main_observable_type,
            "valid_from": valid_from,
            "score": self._resolve_score({"score": related_ioc.get("score")}),
            "external_references": self._build_related_ioc_external_references(
                related_ioc
            ),
        }

    def _collect_page_indicators(
        self, sightings_page: list[dict]
    ) -> tuple[dict, list[dict]]:
        page_indicator_map = {}
        normalized_sightings = []

        for sighting in sightings_page:
            sighted_at = self._parse_datetime(sighting.get("sighted_at"))
            labels = self._extract_sighting_tags(sighting)
            indicator_patterns = []

            for related_ioc in sighting.get("related_iocs") or []:
                normalized_related_ioc = self._normalize_related_ioc(
                    related_ioc=related_ioc,
                    fallback_seen_at=sighted_at,
                )
                if normalized_related_ioc is None:
                    continue

                pattern = normalized_related_ioc["pattern"]
                if pattern not in page_indicator_map:
                    normalized_related_ioc["labels"] = set(labels)
                    page_indicator_map[pattern] = normalized_related_ioc
                else:
                    page_indicator_map[pattern]["labels"].update(labels)

                if pattern not in indicator_patterns:
                    indicator_patterns.append(pattern)

            normalized_sightings.append(
                {
                    "raw_sighting": sighting,
                    "labels": labels,
                    "indicator_patterns": indicator_patterns,
                }
            )

        return page_indicator_map, normalized_sightings

    def _build_indicator_graph(self, indicator_data: dict) -> dict:
        labels = sorted(indicator_data["labels"])
        octi_indicator = Indicator(
            name=indicator_data["ioc_value"],
            pattern_type="stix",
            pattern=indicator_data["pattern"],
            valid_from=indicator_data["valid_from"],
            labels=labels,
            author=self.author,
            markings=[self.marking],
            external_references=indicator_data["external_references"],
            main_observable_type=indicator_data["opencti_main_observable_type"],
            score=indicator_data["score"],
        )

        observable = self._create_observable(
            stix_type=indicator_data["stix_type"],
            stix_path=indicator_data["stix_path"],
            ioc_value=indicator_data["ioc_value"],
            labels=labels,
            score=indicator_data["score"],
        )

        based_on_relationship = None
        if observable is not None:
            based_on_relationship = Relationship(
                type=RelationshipType.BASED_ON,
                source=octi_indicator,
                target=observable,
                author=self.author,
                markings=[self.marking],
            )

        return {
            "indicator": octi_indicator,
            "indicator_ref": Reference(id=octi_indicator.id),
            "observable": observable,
            "based_on_relationship": based_on_relationship,
        }

    def _build_attack_patterns(self, sighting: dict, labels: list[str]) -> list:
        attack_pattern_objects = []

        for attack_pattern_data in self._extract_attack_patterns(sighting):
            kill_chain_phases = None
            tactics = attack_pattern_data.get("tactics") or []
            if not tactics:
                single_tactic = attack_pattern_data.get("tactic")
                if single_tactic:
                    tactics = [single_tactic]

            if tactics:
                kill_chain_phases = []
                for tactic_name in tactics:
                    phase_name = self._normalize_kill_chain_phase_name(tactic_name)
                    if phase_name is not None:
                        kill_chain_phases.append(
                            KillChainPhase(
                                chain_name="mitre-attack",
                                phase_name=phase_name,
                            )
                        )
                if not kill_chain_phases:
                    kill_chain_phases = None

            attack_pattern_objects.append(
                AttackPattern(
                    name=attack_pattern_data["name"],
                    description=attack_pattern_data.get("description"),
                    labels=labels,
                    mitre_id=attack_pattern_data.get("mitre_id"),
                    kill_chain_phases=kill_chain_phases,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        return attack_pattern_objects

    def _build_entities_from_tags(self, sighting: dict) -> list:
        entity_objects = []
        actor_names, malware_names = self._extract_entities_from_sighting_tags(sighting)

        actor_description = sighting.get("apt_description")
        if actor_description and actor_description.strip():
            actor_description = self._strip_html(actor_description) or None
        else:
            actor_description = None

        malware_description = sighting.get("malware_description")
        if malware_description and malware_description.strip():
            malware_description = self._strip_html(malware_description) or None
        else:
            malware_description = None

        for actor_name in actor_names:
            entity_objects.append(
                IntrusionSet(
                    name=actor_name,
                    description=actor_description,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        for malware_name in malware_names:
            entity_objects.append(
                Malware(
                    name=malware_name,
                    is_family=True,
                    description=malware_description,
                    author=self.author,
                    markings=[self.marking],
                )
            )

        return entity_objects

    def _build_indicator_relationships(
        self, indicator_refs: list[Reference], targets: list
    ) -> list:
        relationship_objects = []

        for indicator_ref in indicator_refs:
            for target in targets:
                relationship_objects.append(
                    Relationship(
                        type=RelationshipType.INDICATES,
                        source=indicator_ref,
                        target=target,
                        author=self.author,
                        markings=[self.marking],
                    )
                )

        return relationship_objects

    def _build_stix_sighting(
        self, sighting: dict, indicator_ref: Reference, organization: Organization
    ):
        sighting_id = sighting.get("id")
        sighted_at = self._parse_datetime(sighting.get("sighted_at"))
        if sighting_id is None or sighted_at is None:
            return None

        created = (
            self._parse_datetime(sighting.get("created_at"))
            or sighted_at
            or datetime.now(timezone.utc)
        )
        modified = self._parse_datetime(sighting.get("modified_at")) or created
        stable_id = uuid5(
            NAMESPACE_URL,
            f"flashpoint-sighting:{sighting_id}:{indicator_ref.id}",
        )

        return stix2.Sighting(
            id=f"sighting--{stable_id}",
            sighting_of_ref=indicator_ref.id,
            where_sighted_refs=[organization.id],
            first_seen=sighted_at,
            last_seen=sighted_at,
            count=1,
            description=sighting.get("description") or None,
            created=created,
            modified=modified,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self._build_sighting_external_references(
                    sighting
                )
            ]
            or None,
            allow_custom=True,
        )

    def _build_grouping(self, sighting: dict, labels: list[str], object_refs: list[str]):
        sighting_id = sighting.get("id") or "unknown"
        name = f"Flashpoint sighting {sighting_id}"
        sighted_at = self._parse_datetime(sighting.get("sighted_at"))
        created = (
            self._parse_datetime(sighting.get("created_at"))
            or sighted_at
            or datetime.now(timezone.utc)
        )
        modified = self._parse_datetime(sighting.get("modified_at")) or created

        return stix2.Grouping(
            id=PyctiGrouping.generate_id(name=name, context="suspicious-activity"),
            name=name,
            description=sighting.get("description") or None,
            context="suspicious-activity",
            object_refs=sorted(set(object_refs)),
            created=created,
            modified=modified or created,
            labels=labels or None,
            created_by_ref=self.author.id,
            object_marking_refs=[self.marking.id],
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self._build_sighting_external_references(
                    sighting
                )
            ]
            or None,
            allow_custom=True,
        )

    def convert_sightings_page_to_stix(self, sightings_page: list[dict]) -> list:
        page_indicator_map, normalized_sightings = self._collect_page_indicators(
            sightings_page
        )
        if not page_indicator_map:
            return []

        indicator_graph_by_pattern = {}
        octi_objects = []

        for pattern, indicator_data in page_indicator_map.items():
            indicator_graph = self._build_indicator_graph(indicator_data)
            indicator_graph_by_pattern[pattern] = indicator_graph
            octi_objects.append(indicator_graph["indicator"])
            if indicator_graph["observable"] is not None:
                octi_objects.append(indicator_graph["observable"])
            if indicator_graph["based_on_relationship"] is not None:
                octi_objects.append(indicator_graph["based_on_relationship"])

        for normalized_sighting in normalized_sightings:
            raw_sighting = normalized_sighting["raw_sighting"]
            indicator_patterns = normalized_sighting["indicator_patterns"]
            if not indicator_patterns:
                continue

            source = raw_sighting.get("source")
            if not source or not source.strip():
                continue

            organization = Organization(
                name=source.strip(),
                author=self.author,
                markings=[self.marking],
            )
            sighting_object_refs = [organization.id]
            indicator_refs = []

            for pattern in indicator_patterns:
                indicator_graph = indicator_graph_by_pattern[pattern]
                indicator_refs.append(indicator_graph["indicator_ref"])
                sighting_object_refs.append(indicator_graph["indicator"].id)

                observable = indicator_graph["observable"]
                if observable is not None:
                    sighting_object_refs.append(observable.id)

                based_on_relationship = indicator_graph["based_on_relationship"]
                if based_on_relationship is not None:
                    sighting_object_refs.append(based_on_relationship.id)

            octi_objects.append(organization)

            attack_patterns = self._build_attack_patterns(
                sighting=raw_sighting,
                labels=normalized_sighting["labels"],
            )
            octi_objects.extend(attack_patterns)
            sighting_object_refs.extend(
                attack_pattern.id for attack_pattern in attack_patterns
            )

            attack_pattern_relationships = self._build_indicator_relationships(
                indicator_refs=indicator_refs,
                targets=attack_patterns,
            )
            octi_objects.extend(attack_pattern_relationships)
            sighting_object_refs.extend(
                relationship.id for relationship in attack_pattern_relationships
            )

            entities = self._build_entities_from_tags(raw_sighting)
            octi_objects.extend(entities)
            sighting_object_refs.extend(entity.id for entity in entities)

            entity_relationships = self._build_indicator_relationships(
                indicator_refs=indicator_refs,
                targets=entities,
            )
            octi_objects.extend(entity_relationships)
            sighting_object_refs.extend(
                relationship.id for relationship in entity_relationships
            )

            for indicator_ref in indicator_refs:
                stix_sighting = self._build_stix_sighting(
                    sighting=raw_sighting,
                    indicator_ref=indicator_ref,
                    organization=organization,
                )
                if stix_sighting is None:
                    continue
                octi_objects.append(stix_sighting)
                sighting_object_refs.append(stix_sighting.id)

            octi_objects.append(
                self._build_grouping(
                    sighting=raw_sighting,
                    labels=normalized_sighting["labels"],
                    object_refs=sighting_object_refs,
                )
            )

        return octi_objects
