"""Shared Lambda logging setup, built on aws-lambda-powertools.

aws-lambda-powertools is an optional dependency (the 'lambda' extra), so importing this module
without it installed raises a clear, actionable error instead of a bare ModuleNotFoundError.
"""

try:
    from aws_lambda_powertools import Logger
    from aws_lambda_powertools.logging import utils
except ImportError as error:
    msg = (
        "aws-lambda-powertools is required to use awsfindingsmanagerlib.aws_lambda handlers. "
        "Install it with the 'lambda' extra, e.g. `uv add 'awsfindingsmanagerlib[lambda]'` "
        "or `pip install 'awsfindingsmanagerlib[lambda]'`."
    )
    raise ImportError(msg) from error


def get_logger() -> Logger:
    """Create a powertools Logger and propagate its configuration to other registered loggers.

    The service name is taken from the `POWERTOOLS_SERVICE_NAME` environment variable, as usual
    for aws-lambda-powertools. Handlers built on this logger call `inject_lambda_context()`
    without an explicit `log_event` argument, so whether the incoming event is logged (which can
    include full Security Hub finding payloads) is controlled entirely by the
    `POWERTOOLS_LOGGER_LOG_EVENT` environment variable (defaults to `false`); passing
    `log_event=True`/`False` explicitly at the call site would silently override that setting.

    Returns
    -------
    Logger
        A ready-to-use powertools Logger.
    """
    logger = Logger()
    utils.copy_config_to_registered_loggers(source_logger=logger)
    return logger
