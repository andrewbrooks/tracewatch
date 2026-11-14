import logging

import pytest

from tracewatch import log
from tracewatch.cli import main


@pytest.fixture
def clean_logger():
    logger = logging.getLogger(log.ROOT)
    before = (logger.level, list(logger.handlers))
    yield logger
    logger.setLevel(before[0])
    logger.handlers[:] = before[1]


def test_default_shows_warnings_but_not_debug(clean_logger, capsys):
    log.configure()
    child = logging.getLogger("tracewatch.example")
    child.debug("hidden detail")
    child.warning("something skipped")
    err = capsys.readouterr().err
    assert "something skipped" in err and "hidden detail" not in err
    assert err.startswith("tracewatch: WARNING: ")


def test_verbose_shows_debug(clean_logger, capsys):
    log.configure(verbose=True)
    logging.getLogger("tracewatch.example").debug("a detail")
    assert "tracewatch: DEBUG: a detail" in capsys.readouterr().err


def test_configure_twice_does_not_duplicate_output(clean_logger, capsys):
    log.configure()
    log.configure()
    logging.getLogger("tracewatch.example").warning("once")
    assert capsys.readouterr().err.count("once") == 1


def test_cli_verbose_flag_sets_debug(clean_logger, tmp_path, capsys):
    # a command that fails fast and needs no Docker: a run directory that does not exist
    assert main(["-v", "report", str(tmp_path / "missing")]) == 2
    assert logging.getLogger(log.ROOT).level == logging.DEBUG
    main(["report", str(tmp_path / "missing")])
    assert logging.getLogger(log.ROOT).level == logging.WARNING
