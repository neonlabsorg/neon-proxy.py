import logging
import functools

_LOG = logging.getLogger(__name__)


@functools.cache
def get_core_api_log_level() -> str:
    log_level_dict = {
        logging.CRITICAL: "off",
        logging.ERROR: "error",
        logging.WARNING: "warn",
        logging.INFO: "info",
        logging.DEBUG: "debug",
        logging.NOTSET: "warn",
    }
    level = _LOG.getEffectiveLevel()
    return log_level_dict.get(level, "warn")
