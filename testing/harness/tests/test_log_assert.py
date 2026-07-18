import json

from harness.log_assert import (
    parse_webloginlog,
    count_matching,
    assert_logged,
    double_completion_after_save_failure,
)

# `log show --style ndjson` emits one JSON object per line, plus non-JSON
# header/footer lines the parser must ignore.
NDJSON = """\
{"eventMessage":"webloginlog: viewDidLoad","subsystem":"no.uio.WebloginSSO"}
some non-json banner line that log show prints
{"eventMessage":"unrelated chatter from another process"}
{"eventMessage":"webloginlog: Failed to save the configuration Error 1."}
{"eventMessage":"webloginlog: The audience in user registration is: aud"}
"""

FIXED_LOG = """\
{"eventMessage":"webloginlog: Starting user registration"}
{"eventMessage":"webloginlog: Failed to save the configuration Error 1."}
"""


def test_parse_extracts_only_webloginlog_messages_in_order():
    msgs = parse_webloginlog(NDJSON)
    assert msgs == [
        "webloginlog: viewDidLoad",
        "webloginlog: Failed to save the configuration Error 1.",
        "webloginlog: The audience in user registration is: aud",
    ]


def test_count_matching_counts_substring_hits():
    msgs = parse_webloginlog(NDJSON)
    assert count_matching(msgs, "viewDidLoad") == 1
    assert count_matching(msgs, "not present") == 0


def test_assert_logged_passes_when_present_and_raises_when_absent():
    msgs = parse_webloginlog(NDJSON)
    assert_logged(msgs, "viewDidLoad")  # no raise
    try:
        assert_logged(msgs, "nope")
        assert False, "expected AssertionError"
    except AssertionError:
        pass


def test_double_completion_signature_detected_in_buggy_log():
    # Save failure FOLLOWED BY the password success-path log == pre-89c5a0a bug.
    assert double_completion_after_save_failure(parse_webloginlog(NDJSON)) is True


def test_no_double_completion_in_fixed_log():
    assert double_completion_after_save_failure(parse_webloginlog(FIXED_LOG)) is False


def test_success_path_before_save_failure_is_not_double_completion():
    # Ordering matters: the success-path line BEFORE a save failure is the
    # normal successful-registration sequence, not the 89c5a0a signature.
    log = (
        '{"eventMessage":"webloginlog: The audience in user registration is: aud"}\n'
        '{"eventMessage":"webloginlog: Failed to save the configuration Error 1."}\n'
    )
    assert double_completion_after_save_failure(parse_webloginlog(log)) is False


def test_log_commands_own_invocation_record_is_excluded():
    # `log show` logs its own argv, which contains the literal predicate string —
    # without a process filter every query self-matches and empty runs pass falsely.
    self_match = json.dumps({
        "eventMessage": "log run noninteractively, args: 'log' 'show' '--predicate' "
                        "'eventMessage CONTAINS \"webloginlog:\"'",
        "processImagePath": "/usr/bin/log",
    })
    real = json.dumps({
        "eventMessage": "webloginlog: viewDidLoad",
        "processImagePath": "/Applications/Weblogin SSO.app/Contents/PlugIns/ssoe.appex/Contents/MacOS/ssoe",
    })
    assert parse_webloginlog(self_match + "\n" + real + "\n") == ["webloginlog: viewDidLoad"]
