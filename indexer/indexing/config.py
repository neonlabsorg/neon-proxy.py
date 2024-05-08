import logging

from common.config.config import Config, StartSlot

_LOG = logging.getLogger(__name__)


def get_config_start_slot(cfg: Config, first_slot: int, finalized_slot: int, last_known_slot: int) -> int:
    cfg_start_slot = _get_cfg_start_slot(cfg, last_known_slot, finalized_slot)

    start_slot = max(cfg_start_slot, first_slot)
    _LOG.info(
        "FIRST_AVAILABLE_SLOT=%s, FINALIZED_SLOT=%s, %s=%s, started from the slot %s",
        first_slot,
        finalized_slot,
        cfg.start_slot_name,
        cfg_start_slot,
        start_slot,
    )
    return start_slot


def _get_cfg_start_slot(cfg: Config, last_known_slot: int, finalized_slot: int) -> int:
    """This function allow to skip some part of history.
    - LATEST - start from the last block slot from Solana
    - CONTINUE - the first start from the LATEST, on next starts from the last parsed slot
    - INTEGER - the first start from the INTEGER, on next starts CONTINUE
    """
    last_known_slot = 0 if not isinstance(last_known_slot, int) else last_known_slot

    start_slot = cfg.start_slot
    _LOG.info("starting with LAST_KNOWN_SLOT=%s and %s=%s", last_known_slot, cfg.start_slot_name, start_slot)

    if isinstance(start_slot, int):
        if start_slot > finalized_slot:
            _LOG.info(
                "%s=%s is bigger than finalized slot, forced to use the Solana's finalized slot",
                cfg.start_slot_name,
                start_slot,
            )
            start_slot = StartSlot.Latest

    elif start_slot not in (StartSlot.Continue, StartSlot.Latest):
        _LOG.error("wrong value %s=%s, forced to use %s=0", cfg.start_slot_name, start_slot, cfg.start_slot_name)
        start_slot = 0

    if start_slot == StartSlot.Continue:
        if last_known_slot > 0:
            _LOG.info("%s=%s, started from the last run %s", cfg.start_slot_name, start_slot, last_known_slot)
            return last_known_slot
        else:
            _LOG.info("%s=%s, forced to use the Solana's finalized slot", cfg.start_slot_name, start_slot)
            start_slot = StartSlot.Latest

    if start_slot == StartSlot.Latest:
        _LOG.info("%s=%s, started from the Solana's finalized slot %s", cfg.start_slot_name, start_slot, finalized_slot)
        return finalized_slot

    assert isinstance(start_slot, int)
    if start_slot < last_known_slot:
        _LOG.info("%s=%s, started from the last run %s", cfg.start_slot_name, start_slot, last_known_slot)
        return last_known_slot

    _LOG.info("%s=%s, started from the config start slot %s", cfg.start_slot_name, start_slot, start_slot)
    return start_slot
