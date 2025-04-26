# /usr/lib/python3/dist-packages/cloudinit/config/cc_whitelist_filter.py

import logging
from cloudinit import util
from cloudinit import stages
from cloudinit.cloud import Cloud
from cloudinit.config import Config
from cloudinit.config.schema import MetaSchema

LOG = logging.getLogger(__name__)

meta: MetaSchema = {
    "id": "cc_whitelist_filter",
    "distros": ["all"],
    "frequency": stages.PER_ALWAYS,
    "activate_by_schema_keys": [],
}

# Define keys related to cloud-init module configuration that should *always* be blocked
# Users should not be able to modify these via user-data.
FORBIDDEN_KEYS = {
    "cloud_init_modules",
    "cloud_config_modules",
    "cloud_final_modules",
    "datasource_list", # Preventing modification of datasource detection
    # Add any other cloud-init internal config keys you want to protect
}

# Define the configuration key for this module within cloud.cfg
MODULE_CONFIG_KEY = "cc_whitelist_filter"
WHITELIST_KEY = "allowed_keys"

def handle(name: str, cfg: Config, cloud: Cloud, args: list) -> None:
    """
    Cloud-init handler function.

    Filters the main configuration dictionary 'cfg' based on a whitelist
    defined in cloud-init's system configuration. Also removes known
    forbidden keys related to cloud-init's module execution.
    """
    LOG.debug(f"Running {name} module.")

    # Get the configuration specific to this module from the merged system config
    # This is read from /etc/cloud/cloud.cfg and .d files, NOT from user-data
    module_cfg = util.get_cfg_by_path(cloud.cfg, (MODULE_CONFIG_KEY,), {})
    allowed_keys_cfg = module_cfg.get(WHITELIST_KEY)

    if allowed_keys_cfg is None:
        LOG.warning(
            f"{name}: No '{WHITELIST_KEY}' defined under '{MODULE_CONFIG_KEY}' "
            "in system config (/etc/cloud/cloud.cfg or .d/). "
            "Filtering will remove all user-data keys except known safe defaults."
            # Or choose to error out:
            # raise ValueError(f"Whitelist configuration '{WHITELIST_KEY}' not found.")
        )
        # Default to an empty set, effectively blocking most things if not configured
        allowed_keys = set()
    elif not isinstance(allowed_keys_cfg, list):
        LOG.error(
            f"{name}: Configuration '{WHITELIST_KEY}' must be a list. "
            "Filtering will remove all user-data keys."
        )
        allowed_keys = set()
    else:
        # Convert list to set for efficient lookup, ensure lowercase
        allowed_keys = {str(key).lower() for key in allowed_keys_cfg}
        LOG.debug(f"{name}: Using whitelist: {sorted(list(allowed_keys))}")

    # Add known safe/essential keys that should generally always be allowed
    # (adjust this list based on your needs)
    # allowed_keys.add("users") # Example if 'users' is considered safe by default

    # Iterate through a copy of the keys in the user-data derived config dict
    # We iterate a copy because we modify the original dict 'cfg'
    keys_to_check = list(cfg.keys())
    keys_removed_forbidden = []
    keys_removed_whitelist = []

    for key in keys_to_check:
        key_lower = key.lower()

        # 1. Check against explicitly forbidden keys
        if key_lower in FORBIDDEN_KEYS:
            LOG.warning(
                f"{name}: Removing forbidden configuration key '{key}' "
                "from user-data."
            )
            del cfg[key]
            keys_removed_forbidden.append(key)
            continue # Skip whitelist check if already forbidden

        # 2. Check against the configured whitelist
        if key_lower not in allowed_keys:
            LOG.info(
                f"{name}: Removing key '{key}' from user-data because it's "
                f"not in the configured whitelist ('{WHITELIST_KEY}')."
            )
            del cfg[key]
            keys_removed_whitelist.append(key)

    if keys_removed_forbidden:
        LOG.warning(f"{name}: Removed forbidden keys: {keys_removed_forbidden}")
    if keys_removed_whitelist:
        LOG.info(f"{name}: Removed non-whitelisted keys: {keys_removed_whitelist}")

    LOG.debug(f"{name}: Filtering complete.")