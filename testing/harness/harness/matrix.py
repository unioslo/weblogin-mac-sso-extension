from __future__ import annotations
import re
from dataclasses import dataclass
from xml.etree import ElementTree as ET


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    status: str  # "pass" | "fail" | "skip"


def _short_name(testcase_name: str) -> str:
    """`test_scenario[happy_path]` -> `happy_path`; fall back to the raw name."""
    m = re.search(r"\[(.+)\]", testcase_name)
    return m.group(1) if m else testcase_name


def parse_junit(xml_text: str) -> list[ScenarioResult]:
    root = ET.fromstring(xml_text)
    results: list[ScenarioResult] = []
    for case in root.iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            status = "fail"
        elif case.find("skipped") is not None:
            status = "skip"
        else:
            status = "pass"
        results.append(ScenarioResult(name=_short_name(case.get("name", "")), status=status))
    return results


def render_matrix(results: list[ScenarioResult]) -> str:
    lines = ["| Scenario | Result |", "| --- | --- |"]
    if not results:
        lines.append("| _no scenarios ran_ | — |")
    for r in results:
        lines.append(f"| {r.name} | {r.status} |")
    return "\n".join(lines) + "\n"
