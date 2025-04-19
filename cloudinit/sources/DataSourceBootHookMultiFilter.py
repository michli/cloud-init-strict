# /usr/lib/python3/dist-packages/cloudinit/sources/DataSourceBootHookMultiFilter.py

import logging
import re
import os
import signal
import time

from cloudinit import sources
from cloudinit import util
from cloudinit.sources import DataSource
# No longer need stages import

LOG = logging.getLogger(__name__)

# Regex for filtering
BOOTHOK_RE = re.compile(
    rb'^#cloud-boothook.*?(?=^#\w|\Z)', re.MULTILINE | re.DOTALL
)

datasource_depends = [
    [sources.DEP_FILESYSTEM],  # Run at init-local
    [sources.DEP_FILESYSTEM, sources.DEP_NETWORK],
]

# filter_boothooks function (ensure bytes handling is correct)
def filter_boothooks(userdata_raw, log):
    if not userdata_raw: return userdata_raw
    # Ensure we are working with bytes
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
         # Return in the original type
         return userdata_raw

    log.info("Found #cloud-boothook directive, filtering user-data...")
    filtered_bytes = BOOTHOK_RE.sub(b'', userdata_bytes).strip()
    log.info("Filtering complete.")

    # Return in the original type
    if original_type is str:
        return filtered_bytes.decode('utf-8')
    else:
        return filtered_bytes


class DatasourceTimeoutError(Exception):
    """Custom exception for datasource check timeouts."""
    pass

class DataSourceBootHookMultiFilter(DataSource):
    ds_priority = 10

    def __init__(self, sys_cfg, distro, paths):
        super(DataSourceBootHookMultiFilter, self).__init__(sys_cfg, distro, paths)
        self.underlying_ds_instance = None
        self.underlying_ds_name = None
        # Remove _initialized_underlying flag, detection runs when needed

    def _find_and_set_underlying_ds(self):
        """
        (Internal) Iterates through potential datasources (excluding self)
        using standard cloud-init source listing and initialization checks
        to find the currently active one based on the current cloud-init stage
        and network availability implicitly checked by candidate.get_data().
        Sets self.underlying_ds_instance and self.underlying_ds_name upon success.
        Returns True if a functional DS was found, False otherwise.
        """
        # Avoid infinite recursion if called internally by delegated methods
        # while still trying to initialize. Check if already found.
        if self.underlying_ds_instance is not None:
             return True

        LOG.info("DataSourceBootHookMultiFilter: Attempting to detect functional underlying datasource...")

        my_name = self.__class__.__name__[len("DataSource"):]
        original_ds_list = self.sys_cfg.get('datasource_list', [])
        detection_list_names = [ds_name for ds_name in original_ds_list if ds_name != my_name]

        if not detection_list_names:
            LOG.error("DataSourceBootHookMultiFilter: Cannot detect underlying datasource - none configured.")
            return False

        LOG.debug(f"DataSourceBootHookMultiFilter: Detection candidates: {detection_list_names}")

        try:
            # Use empty list for depends - let candidate.get_data() determine stage suitability
            depends_param = [sources.DEP_FILESYSTEM, sources.DEP_NETWORK]
            # Use empty list for pkg_list - rely on sys.path
            pkg_list_param = ['cloudinit.sources']
            LOG.debug(f"DataSourceBootHookMultiFilter: Calling list_sources with depends={depends_param}, pkg_list={pkg_list_param}")
            avail_sources_items = sources.list_sources(detection_list_names, depends_param, pkg_list_param)
            LOG.debug(f"DataSourceBootHookMultiFilter: list_sources returned: {avail_sources_items}")
        except Exception as e:
            LOG.error(f"DataSourceBootHookMultiFilter: Failed to list available sources: {e}")
            util.logexc(LOG, "Listing sources failed")
            return False # Cannot proceed without list

        available_sources_map = {}
        if not avail_sources_items: # Check if list is empty or None
             LOG.warning("DataSourceBootHookMultiFilter: list_sources returned no items.")
        else:
             try:
                 for item in avail_sources_items:
                     # Handle potential variations in list_sources return format
                     if isinstance(item, tuple) and len(item) == 2:
                         name, kls = item # Assume (name, class) tuples
                     elif isinstance(item, type) and issubclass(item, DataSource):
                         kls = item      # Assume just class type
                         name = kls.__name__ # Derive name
                     else:
                         LOG.warning(f"Unexpected item format from list_sources: {item}")
                         continue

                     if name.startswith("DataSource"):
                          map_name = name[len("DataSource"):]
                     else:
                          map_name = name
                     available_sources_map[map_name] = kls

             except Exception as e:
                 LOG.error(f"Error processing list_sources results: {e}")
                 util.logexc(LOG, "Processing available sources failed")
                 # Proceed with potentially empty map

        LOG.debug(f"DataSourceBootHookMultiFilter: available_sources_map: {available_sources_map}")

        detected_ds = None
        detected_ds_name = None
        timeout_seconds = 10

        def _handle_timeout(signum, frame):
            raise DatasourceTimeoutError(f"Datasource check timed out after {timeout_seconds} seconds")

        for ds_name, ds_kls in available_sources_map.items():
            LOG.debug(f"DataSourceBootHookMultiFilter: Checking candidate '{ds_name}'...")

            old_handler = signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(timeout_seconds)
            start_time = time.monotonic()
            check_success = False
            candidate_ds = None

            try:
                # Instantiate the candidate DS
                candidate_ds = ds_kls(self.sys_cfg, self.distro, self.paths)
                # Check if it's functional *in the current context* (local or network stage)
                if candidate_ds.get_data():
                     check_success = True
                else:
                     check_success = False

            except DatasourceTimeoutError as e_timeout:
                LOG.warning(f"DataSourceBootHookMultiFilter: Check timed out for '{ds_name}': {e_timeout}")
            except sources.DataSourceNotFoundException:
                LOG.debug(f"DataSourceBootHookMultiFilter: Not found/applicable in current environment: '{ds_name}'.")
            except Exception as e:
                LOG.warning(f"DataSourceBootHookMultiFilter: Error checking '{ds_name}': {e}")
                util.logexc(LOG, f"Datasource {ds_name} check failed")
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
                end_time = time.monotonic()

            duration_ms = (end_time - start_time) * 1000

            if check_success:
                LOG.info(f"DataSourceBootHookMultiFilter: Detected functional underlying datasource: '{ds_name}' after {duration_ms:.2f}ms")
                detected_ds = candidate_ds
                detected_ds_name = ds_name
                break # Found the first working datasource
            else:
                if candidate_ds is not None:
                     LOG.debug(f"DataSourceBootHookMultiFilter: Check failed/returned False for '{ds_name}' after {duration_ms:.2f}ms.")

        if detected_ds:
            self.underlying_ds_instance = detected_ds
            self.underlying_ds_name = detected_ds_name
            return True # Indicate success
        else:
            LOG.warning("DataSourceBootHookMultiFilter: No functional underlying datasource detected.")
            # Keep self.underlying_ds_instance as None
            return False # Indicate failure

    def _get_underlying_ds(self):
        """
        Ensures underlying DS is detected *if not already set* and returns the instance.
        Calls detection logic only if necessary.
        """
        if self.underlying_ds_instance is None:
            self._find_and_set_underlying_ds() # Attempt detection now
        return self.underlying_ds_instance

    # --- Filtering and Delegation Logic ---

    def get_data(self):
        """
        Try to detect underlying DS if not already done.
        Return True if underlying DS detection is successful, False otherwise.
        The actual data fetch happens within the detected underlying DS.
        """
        # The main purpose of this proxy's get_data is just to ensure
        # that an underlying source *can* be found eventually.
        uds = self._get_underlying_ds() # This triggers detection if needed
        # If detection was successful (now or previously), return True.
        # If detection failed, _get_underlying_ds returns None, so return False.
        return uds is not None

    def get_userdata_raw(self):
        """
        Ensure underlying DS is detected, then delegate, filter, and return.
        """
        uds = self._get_underlying_ds() # Triggers detection if needed
        if not uds:
            LOG.warning("DataSourceBootHookMultiFilter: Cannot get user-data, no underlying datasource found.")
            return None

        LOG.debug(f"DataSourceBootHookMultiFilter: Requesting raw user-data from underlying '{self.underlying_ds_name}'")
        try:
            original_userdata = uds.get_userdata_raw()
        except Exception as e:
            # ... (error handling) ...
            LOG.error(f"DataSourceBootHookMultiFilter: Failed to get user-data from underlying DS: {e}")
            util.logexc(LOG, "Underlying get_userdata_raw failed")
            return None


        if original_userdata is None:
            # ... (debug log) ...
            LOG.debug("DataSourceBootHookMultiFilter: Underlying datasource returned no user-data.")
            return None


        # Filter the fetched data
        filtered_userdata = filter_boothooks(original_userdata, LOG)

        # Update underlying cache (optional but safer)
        if hasattr(uds, 'userdata_raw'):
             uds.userdata_raw = filtered_userdata # Store filtered version back
             LOG.debug("DataSourceBootHookMultiFilter: Updated underlying datasource's userdata_raw attribute.")

        return filtered_userdata

    # --- Delegate other essential DataSource methods ---
    # Methods like get_instance_id, get_public_ssh_keys, etc., MUST call
    # self._get_underlying_ds() first to ensure detection has happened.

    @property
    def platform(self):
        uds = self._get_underlying_ds()
        return uds.platform if uds else "proxy"

    @property
    def subplatform(self):
        uds = self._get_underlying_ds()
        return getattr(uds, 'subplatform', 'filtered-proxy') if uds else "filtered-proxy"

    def get_instance_id(self):
        uds = self._get_underlying_ds() # Ensures detection
        return uds.get_instance_id() if uds else "iid-proxy-unknown"

    def get_public_ssh_keys(self):
        uds = self._get_underlying_ds() # Ensures detection
        return uds.get_public_ssh_keys() if uds else []

    def get_hostname(self, fqdn=False, metadata_only=False):
        uds = self._get_underlying_ds() # Ensures detection
        if uds and hasattr(uds, 'get_hostname'):
             return uds.get_hostname(fqdn=fqdn, metadata_only=metadata_only)
        return super(DataSourceBootHookMultiFilter, self).get_hostname(fqdn=fqdn, metadata_only=metadata_only)

    def get_locale(self):
        uds = self._get_underlying_ds() # Ensures detection
        return uds.get_locale() if uds else "en_US.UTF-8"

# Required function for cloud-init to discover this datasource
def get_datasource_list(depends):
    # This filter is suitable for *any* dependency stage, as it relies
    # on the underlying DS check to determine suitability.
    return [DataSourceBootHookMultiFilter]