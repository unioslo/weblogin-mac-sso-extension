from harness.matrix import ScenarioResult, parse_junit, render_matrix

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" tests="3" failures="1" skipped="1">
    <testcase classname="scenarios.test_scenarios" name="test_scenario[happy_path]"/>
    <testcase classname="scenarios.test_scenarios" name="test_scenario[token_500]">
      <failure message="assert 500">boom</failure>
    </testcase>
    <testcase classname="scenarios.test_scenarios" name="test_scenario[profile_repush]">
      <skipped message="needs nanomdm live"/>
    </testcase>
  </testsuite>
</testsuites>
"""


def test_parse_junit_maps_status_per_case():
    results = parse_junit(JUNIT)
    by_name = {r.name: r.status for r in results}
    assert by_name == {
        "happy_path": "pass",
        "token_500": "fail",
        "profile_repush": "skip",
    }


def test_render_matrix_is_a_markdown_table_with_a_row_per_scenario():
    md = render_matrix(
        [
            ScenarioResult(name="happy_path", status="pass"),
            ScenarioResult(name="token_500", status="fail"),
            ScenarioResult(name="profile_repush", status="skip"),
        ]
    )
    assert "| Scenario | Result |" in md
    assert "| happy_path | pass |" in md
    assert "| token_500 | fail |" in md
    assert "| profile_repush | skip |" in md


def test_render_matrix_handles_empty_results():
    md = render_matrix([])
    assert "| Scenario | Result |" in md
    assert "_no scenarios ran_" in md
