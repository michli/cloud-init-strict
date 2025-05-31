import logging
from cloudinit import util

# Global constant defining keys that represent lists of cloud-init modules.
CFG_MODULE_LISTS = ["cloud_init_modules", "cloud_config_modules", "cloud_final_modules"]

LOG = logging.getLogger(__name__)

class AllowKeyFilter:
    """
    Filters a configuration dictionary based on an allow-list defined
    within a base configuration.

    This class is designed to process a raw configuration and return a new
    configuration containing only the keys (and their nested structures)
    that are explicitly permitted by an 'allow_keys' section in a
    base configuration.
    """

    def __init__(self, base_cfg: dict) -> None:
        self._base_cfg = base_cfg

    def filter(self, raw_cfg: dict) -> dict:
        """
        Applies the allow-key filter to a raw configuration dictionary.

        If no 'allow_keys' are defined in the base configuration, the
        original raw configuration is returned unmodified. Otherwise, a
        new dictionary is returned containing only the allowed keys and
        their corresponding values from the raw configuration.

        Args:
            raw_cfg (dict): The raw configuration dictionary to be filtered.

        Returns:
            dict: A new dictionary containing only the allowed keys and values,
                  or the original raw_cfg if no filter rules are defined.
        """
        filter_cfg = self._load_filter_cfg()
        if filter_cfg:
            allow_keys = self._gen_key_list(filter_cfg)
            LOG.debug(f"allow keys: {str(allow_keys)}")
            return self._do_filter(raw_cfg, allow_keys)
        return raw_cfg

    def _load_filter_cfg(self) -> dict | None:
        return self._base_cfg.get("allow_keys", None) if self._base_cfg else None

    def _gen_key_list(self, filter_cfg: dict) -> dict:
        filter_dict = dict()
        for k, v in filter_cfg.items():
            if k in CFG_MODULE_LISTS:
                filter_dict.update(self._gen_module_cfg_filter(k, v))
            else:
                filter_dict[k] = self._gen_other_filter(v)
        return filter_dict

    def _gen_module_cfg_filter(self, cfg_key: str, cfg_value) -> dict:
        filtered = dict()
        if isinstance(cfg_value, str):
            if cfg_value == 'CONFIG' or cfg_value == 'CUSTOM':
                configured_modules = self._load_option_list(cfg_key)
                for item in configured_modules:
                    name = self._parse_module_config(item)
                    if name:
                        filtered[name] = None  # Allow the module's configuration
                if cfg_value == 'CUSTOM':
                    # Allow the module list key itself (e.g., 'cloud_config_modules')
                    # so users can provide a custom list directly.
                    filtered[cfg_key] = None
            else:
                # If cfg_value is a simple string (not 'CONFIG' or 'CUSTOM'),
                # it's treated as a single module name to allow.
                filtered[str(cfg_value)] = None
        elif isinstance(cfg_value, list):
            for item in cfg_value:
                name = self._parse_module_config(item)
                if name:
                    filtered[name] = None  # Allow the specified module's configuration
        # ignore other types, as they are not expected in this context
        else:
            LOG.warning(f"Unexpected type for cfg_value in module list '{cfg_key}': {type(cfg_value)}. "
                        f"Expected list or string, but got {cfg_value}. Ignoring this key.")

        return filtered

    def _gen_other_filter(self, cfg_value) -> dict | None:
        filtered = dict()
        if isinstance(cfg_value, dict):
            for k, v in cfg_value.items():
                filtered[k] = self._gen_other_filter(v)
            return filtered
        elif isinstance(cfg_value, list):
            for k_item in cfg_value:
                filtered[str(k_item)] = None # Each item in list is an allowed key
            return filtered
        else:
            # If cfg_value is a simple string or other primitive,
            # it means the key itself is allowed
            if cfg_value is not None:
                filtered[str(cfg_value)] = None
                return filtered
            return None

    def _do_filter(self, raw_cfg: dict, allow_keys: dict, path: list = []) -> dict:
        filtered_cfg = dict()
        if not isinstance(raw_cfg, dict): # Handle cases where raw_cfg might not be a dict
            LOG.error(f"Expected a dictionary for raw_cfg, got {type(raw_cfg)}. "
                      f"Returning empty dict for this level with allow_keys: {allow_keys}")
            return {}

        for k, v in raw_cfg.items():
            if k not in allow_keys:
                LOG.info(f"Ignored user config \"{'/'.join(path + [k])}\": {v}")
                continue
            subfilter = allow_keys[k]
            if isinstance(subfilter, dict): # If there's a sub-filter defined
                if isinstance(v, dict): # And the value is a dict to recurse into
                    filtered_cfg[k] = self._do_filter(v, subfilter, path + [k])
                elif isinstance(v, list): # If the value is a list, filter each item
                    filtered_cfg[k] = [item for item in v if item in subfilter]
                else: # If the value is not a dict or list, just allow it
                    filtered_cfg[k] = v
            else: # If subfilter is None (or not a dict), allow the whole value
                filtered_cfg[k] = v
        return filtered_cfg

    def _load_option_list(self, cfg_name: str) -> list:
        LOG.debug(f"Load cfg for '{cfg_name}'")
        if not self._base_cfg:
            return []
        return util.get_cfg_option_list(self._base_cfg, cfg_name, [])

    def _parse_module_config(self, item) -> str | None:
        if isinstance(item, list):
            if len(item) > 0:
                return str(item[0]) if item[0] is not None else None
            else:
                return None
        elif isinstance(item, str):
            return item
        else:
            # Item is of an unexpected type
            LOG.warning(f"Unexpected item type in module list: {type(item)}, value: {item}. Cannot parse name.")
            return None