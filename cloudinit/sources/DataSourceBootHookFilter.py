# /usr/lib/python3/dist-packages/cloudinit/sources/DataSourceBootHookFilter.py

import logging
import re
import os
import signal
import time

from cloudinit import sources
from cloudinit import util
from cloudinit.sources import DataSource

LOG = logging.getLogger(__name__)

# Regex and filtering function (ensure bytes handling is correct)
BOOTHOK_RE = re.compile(
    rb'^#cloud-boothook.*?(?=^#\w|\Z)', re.MULTILINE | re.DOTALL
)

def filter_boothooks(userdata_raw, log):
    # ... (use the version from the previous successful regex test) ...
    if not userdata_raw: return userdata_raw
    original_type = type(userdata_raw)
    if isinstance(userdata_raw, str):
        userdata_bytes = userdata_raw.encode('utf-8')
    elif isinstance(userdata_raw, bytes):
        userdata_bytes = userdata_raw
    else:
        log.warning(f"Unexpected userdata type {original_type}, skipping filtering.")
        return userdata_raw

    if not re.search(rb'^#cloud-boothook', userdata_bytes, re.MULTILINE):
         log.debug("No #cloud-boothook found, returning original user-data.")
         return userdata_raw

    log.info("Found #cloud-boothook directive, filtering user-data...")
    filtered_bytes = BOOTHOK_RE.sub(b'', userdata_bytes).strip()
    log.info("Filtering complete.")

    if original_type is str:
        return filtered_bytes.decode('utf-8')
    else:
        return filtered_bytes


class DatasourceTimeoutError(Exception):
    """Custom exception for datasource check timeouts."""
    pass

class DataSourceBootHookFilter(DataSource):
    ds_priority = 10

    def __init__(self, sys_cfg, distro, paths):
        super(DataSourceBootHookFilter, self).__init__(sys_cfg, distro, paths)
        self.underlying_ds_instance = None
        self.underlying_ds_name = None
        # No _initialized_underlying flag

    def _try_detect_with_depends(self, depends_param):
        """
        Internal helper to attempt datasource detection with a specific
        dependency list. Sets instance variables upon success.
        Returns True if a functional DS was found, False otherwise.
        """
        my_name = self.__class__.__name__[len("DataSource"):]
        original_ds_list = self.sys_cfg.get('datasource_list', [])
        detection_list_names = [ds_name for ds_name in original_ds_list if ds_name != my_name]

        if not detection_list_names:
            LOG.error(f"FilterDS: Cannot detect, no candidates in {original_ds_list}")
            return False # Should not happen if configured correctly

        LOG.debug(f"FilterDS: Attempting detection with depends={depends_param} for candidates: {detection_list_names}")

        try:
            # Use empty list for pkg_list - rely on sys.path (adjust if needed)
            pkg_list_param = ['cloudinit.sources']
            LOG.debug(f"FilterDS: Calling list_sources with depends={depends_param}, pkg_list={pkg_list_param}")
            avail_sources_items = sources.list_sources(detection_list_names, depends_param, pkg_list_param)
            LOG.debug(f"FilterDS: list_sources for depends={depends_param} returned: {avail_sources_items}")
        except Exception as e:
            LOG.error(f"FilterDS: Failed list_sources for depends={depends_param}: {e}")
            util.logexc(LOG, "Listing sources failed")
            return False

        available_sources_map = {}
        if avail_sources_items: # Check if list is non-empty/not None
            try:
                for item in avail_sources_items:
                    if isinstance(item, tuple) and len(item) == 2: name, kls = item
                    elif isinstance(item, type) and issubclass(item, DataSource): kls = item; name = kls.__name__
                    else: continue
                    map_name = name[len("DataSource"):] if name.startswith("DataSource") else name
                    available_sources_map[map_name] = kls
            except Exception as e:
                LOG.error(f"Error processing list_sources results for depends={depends_param}: {e}")
                # Continue with potentially empty map

        LOG.debug(f"FilterDS: available_sources_map for depends={depends_param}: {available_sources_map}")
        if not available_sources_map:
             LOG.debug(f"FilterDS: No suitable datasource classes found for depends={depends_param}")
             return False # No classes returned for these dependencies

        timeout_seconds = 10
        def _handle_timeout(signum, frame):
            raise DatasourceTimeoutError(f"Datasource check timed out after {timeout_seconds} seconds")

        # Iterate through the *original configured* list to respect order preference
        for ds_name in detection_list_names:
            ds_kls = available_sources_map.get(ds_name) # Check if this DS was returned for current depends
            if not ds_kls:
                # This DS doesn't match the current dependency set, skip it
                continue

            LOG.debug(f"FilterDS: Checking candidate '{ds_name}' (depends={depends_param})...")

            old_handler = signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(timeout_seconds)
            start_time = time.monotonic()
            check_success = False
            candidate_ds = None
            try:
                candidate_ds = ds_kls(self.sys_cfg, self.distro, self.paths)
                if candidate_ds.get_data(): # Check if functional *now*
                     check_success = True
            except DatasourceTimeoutError as e_timeout: LOG.warning(f"FilterDS: Timeout checking '{ds_name}': {e_timeout}")
            except sources.DataSourceNotFoundException: LOG.debug(f"FilterDS: Not found/applicable: '{ds_name}'.")
            except Exception as e: LOG.warning(f"FilterDS: Error checking '{ds_name}': {e}"); util.logexc(LOG, f"{ds_name} check failed")
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
                end_time = time.monotonic()

            duration_ms = (end_time - start_time) * 1000
            if check_success:
                LOG.info(f"FilterDS: Detected functional underlying datasource: '{ds_name}' (depends={depends_param}) after {duration_ms:.2f}ms")
                # Set the instance variables - SUCCESS!
                self.underlying_ds_instance = candidate_ds
                self.underlying_ds_name = ds_name
                return True # Found a functional DS for these depends
            else:
                if candidate_ds is not None: LOG.debug(f"FilterDS: Check failed/False for '{ds_name}' (depends={depends_param}) after {duration_ms:.2f}ms.")

        LOG.debug(f"FilterDS: No functional datasource found for depends={depends_param}.")
        return False # No functional DS found for this dependency set

    def _find_and_set_underlying_ds(self):
        """
        Attempts to find the functional underlying datasource by trying
        different dependency sets relevant to cloud-init stages.
        """
        if self.underlying_ds_instance is not None:
             return True # Already found

        LOG.info("FilterDS: Detecting underlying datasource (multi-stage attempt)...")

        # Attempt 1: Try with dependencies typical for local stage
        # (Only filesystem needed)
        if self._try_detect_with_depends([sources.DEP_FILESYSTEM]):
            return True # Found functional DS in local-like stage

        # Attempt 2: Try with dependencies typical for network stage
        # (Filesystem and Network needed)
        LOG.info("FilterDS: No functional local DS found, trying network-dependent detection...")
        if self._try_detect_with_depends([sources.DEP_FILESYSTEM, sources.DEP_NETWORK]):
             return True # Found functional DS in network-like stage

        # If neither attempt found a functional datasource
        LOG.warning("FilterDS: No functional underlying datasource detected after checking both local and network dependencies.")
        self.underlying_ds_instance = None # Ensure it's None
        self.underlying_ds_name = None
        return False

    def _get_underlying_ds(self):
        """
        Ensures underlying DS is detected *if not already set* and returns the instance.
        Calls detection logic only if necessary.
        """
        # Only run detection if we haven't successfully found one yet.
        if self.underlying_ds_instance is None:
            self._find_and_set_underlying_ds() # Attempt detection now
        return self.underlying_ds_instance

    # --- Filtering and Delegation Logic ---

    def get_data(self):
        """
        Try to detect underlying DS if not already done.
        Return True if underlying DS detection is successful, False otherwise.
        """
        uds = self._get_underlying_ds() # This triggers detection if needed
        return uds is not None

    def get_userdata_raw(self):
        """
        Ensure underlying DS is detected, then delegate, filter, and return.
        """
        uds = self._get_underlying_ds() # Triggers detection if needed
        if not uds:
            LOG.warning("FilterDS: Cannot get user-data, no underlying datasource found.")
            return None

        LOG.debug(f"FilterDS: Requesting raw user-data from underlying '{self.underlying_ds_name}'")
        try:
            original_userdata = uds.get_userdata_raw()
        except Exception as e:
            LOG.error(f"FilterDS: Failed to get user-data from underlying DS: {e}")
            util.logexc(LOG, "Underlying get_userdata_raw failed")
            return None

        if original_userdata is None:
            LOG.debug("FilterDS: Underlying datasource returned no user-data.")
            return None

        # Filter the fetched data
        filtered_userdata = filter_boothooks(original_userdata, LOG)

        # Update underlying cache (optional but safer)
        if hasattr(uds, 'userdata_raw'):
             # Store filtered version back ONLY if filtering actually happened?
             # Or always store the potentially filtered version? Always store is safer.
             uds.userdata_raw = filtered_userdata
             LOG.debug("FilterDS: Updated underlying datasource's userdata_raw attribute.")

        return filtered_userdata

    # --- Delegate other essential DataSource methods ---
    # Methods like get_instance_id, get_public_ssh_keys, etc., MUST call
    # self._get_underlying_ds() first to ensure detection has happened.

    # ... (platform, subplatform, get_instance_id, get_public_ssh_keys, etc.) ...
    # Ensure ALL delegation methods call self._get_underlying_ds() first!
    # Example:
    @property
    def platform(self):
        uds = self._get_underlying_ds()
        # ... rest of method ...
        return uds.platform if uds else "proxy"

    @property
    def subplatform(self):
        uds = self._get_underlying_ds()
        return getattr(uds, 'subplatform', 'filtered-proxy') if uds else "filtered-proxy"

    def get_instance_id(self):
        uds = self._get_underlying_ds()
        return uds.get_instance_id() if uds else "iid-proxy-unknown"

    def get_public_ssh_keys(self):
        uds = self._get_underlying_ds()
        return uds.get_public_ssh_keys() if uds else []

    def get_hostname(self, fqdn=False, metadata_only=False):
        uds = self._get_underlying_ds()
        if uds and hasattr(uds, 'get_hostname'):
             return uds.get_hostname(fqdn=fqdn, metadata_only=metadata_only)
        return super(DataSourceBootHookFilter, self).get_hostname(fqdn=fqdn, metadata_only=metadata_only)

    def get_locale(self):
        uds = self._get_underlying_ds()
        return uds.get_locale() if uds else "en_US.UTF-8"


# Required function for cloud-init to discover this datasource
def get_datasource_list(depends):
    # This filter should be considered regardless of the stage dependencies,
    # as it internally checks for suitability based on underlying DS results.
    return [DataSourceBootHookFilter]