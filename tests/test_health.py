from vajra.health import run_self_test


def test_self_test_is_local_and_explicit():
    result = run_self_test()

    assert result.status == "ok"
    assert result.checks == ("configuration", "package-imports")