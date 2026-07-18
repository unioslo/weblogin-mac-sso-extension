from mock_idp.faults import FaultRegistry, FaultKind


def test_arm_and_consume_once():
    reg = FaultRegistry()
    reg.arm(FaultKind.TOKEN_500, times=1)
    assert reg.consume(FaultKind.TOKEN_500) is True
    assert reg.consume(FaultKind.TOKEN_500) is False  # consumed


def test_arm_multiple_times():
    reg = FaultRegistry()
    reg.arm(FaultKind.BAD_NONCE, times=2)
    assert reg.consume(FaultKind.BAD_NONCE) is True
    assert reg.consume(FaultKind.BAD_NONCE) is True
    assert reg.consume(FaultKind.BAD_NONCE) is False


def test_reset_clears_all():
    reg = FaultRegistry()
    reg.arm(FaultKind.TIMEOUT, times=5)
    reg.reset()
    assert reg.consume(FaultKind.TIMEOUT) is False


def test_unknown_kind_rejected():
    reg = FaultRegistry()
    try:
        reg.arm("not_a_kind", times=1)  # type: ignore[arg-type]
        assert False, "expected ValueError"
    except ValueError:
        pass
