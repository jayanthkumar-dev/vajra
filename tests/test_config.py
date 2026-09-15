from vajra.config import get_settings


def test_default_settings(monkeypatch):
    monkeypatch.delenv("VAJRA_HOST", raising=False)
    monkeypatch.delenv("VAJRA_PORT", raising=False)
    monkeypatch.delenv("VAJRA_LOG_LEVEL", raising=False)

    assert get_settings().host == "127.0.0.1"
    assert get_settings().port == 8000


def test_invalid_port_is_rejected(monkeypatch):
    monkeypatch.setenv("VAJRA_PORT", "not-a-port")

    try:
        get_settings()
    except ValueError as error:
        assert "VAJRA_PORT" in str(error)
    else:
        raise AssertionError("invalid port was accepted")