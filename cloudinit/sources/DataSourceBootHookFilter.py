# /usr/lib/python3/dist-packages/cloudinit/sources/DataSourceBootHookFilter.py

import logging
import re
import os

# Use cloudinit.sources to access detection logic
from cloudinit import sources
from cloudinit import util
from cloudinit.sources import DataSource
from cloudinit import stages

LOG = logging.getLogger(__name__)

# Reuse the filtering function from the previous example
BOOTHOK_RE = re.compile(
    rb'^#cloud-boothook.*(?:\n(?!#).*)*\n?', re.MULTILINE
)

def filter_boothooks(userdata_raw, log):
    if not userdata_raw: return userdata_raw
    if b'#cloud-boothook' not in userdata_raw: return userdata_raw
    log.info("Found #cloud-boothook directive, filtering user-data...")
    filtered_data = BOOTHOK_RE.sub(b'', userdata_raw)
    log.info("Filtering complete.")
    return filtered_data.strip()


class DataSourceBootHookFilter(DataSource):
    # Give it a reasonably high priority so it runs before fallback 'None'
    # but allow standard datasources to be listed after it.
    ds_priority = 10

    def __init__(self, sys_cfg, distro, paths):
        super(DataSourceBootHookFilter, self).__init__(sys_cfg, distro, paths)
        self.underlying_ds_instance = None
        self.underlying_ds_name = None
        # Indicate that we haven't found the underlying DS yet
        self._initialized_underlying = False

    def _find_and_set_underlying_ds(self):
        """
        Iterates through potential datasources (excluding self) using standard
        cloud-init source listing and initialization checks to find the active one.
        """
        if self._initialized_underlying:
            return self.underlying_ds_instance is not None

        LOG.info("MyFilteringProxy: Attempting to detect underlying datasource by iterating...")

        my_name = self.__class__.__name__

        # 1. Get the configured list of datasource names to try (cfg_list for list_sources)
        original_ds_list = self.sys_cfg.get('datasource_list', [])
        detection_list_names = [ds_name for ds_name in original_ds_list if ds_name != my_name]

        if not detection_list_names:
            LOG.error("MyFilteringProxy: Original datasource list contains no other datasources to detect!")
            self._initialized_underlying = True
            return False

        LOG.debug(f"MyFilteringProxy: Will attempt detection by trying datasources in order: {detection_list_names}")

        # 2. Get the available datasource classes known to cloud-init
        try:
            # Define dependencies and package list for list_sources
            depends_param = []  # Dependencies we are matching
            pkg_list_param = ['cloudinit.sources'] 
            LOG.debug(f"MyFilteringProxy: pkg_list_param: {pkg_list_param}")

            # *** CORRECTED CALL to list_sources using positional arguments ***
            avail_sources_items = sources.list_sources(detection_list_names, depends_param, pkg_list_param)
            LOG.debug(f"MyFilteringProxy: list_sources returned: {avail_sources_items}")
        except Exception as e:
            LOG.error(f"MyFilteringProxy: Failed to list available sources: {e}")
            util.logexc(LOG, "Listing sources failed")
            self._initialized_underlying = True
            return False

        # 3. Iterate through the *returned* available source items (name, class tuples)
        #    matching them against the *configured* detection list order.
        #    Note: list_sources might return classes not in detection_list_names if called differently,
        #    but here it should only return classes *derived from* checking the names we provided.
        #    We still iterate through detection_list_names to maintain specified order preference.

        available_sources_map = {} # Map name to class for lookup
        for kls in avail_sources_items:
            class_name = kls.__name__
            if class_name.startswith("DataSource"):
                available_sources_map[class_name[len("DataSource"):]] = kls
            else:
                available_sources_map[class_name] = kls

        LOG.debug(f"MyFilteringProxy: available_sources_map: {available_sources_map}")

        detected_ds = None
        detected_ds_name = None
        for ds_name in detection_list_names:
            LOG.debug(f"MyFilteringProxy: Checking candidate datasource '{ds_name}'...")
            # ds_kls = sources.find_source_class(ds_name, avail_sources_items) # Don't need this if using map
            ds_kls = available_sources_map.get(ds_name) # Lookup class from map

            if not ds_kls:
                LOG.debug(f"MyFilteringProxy: No class found or returned by list_sources for datasource '{ds_name}', skipping.")
                continue

            # 4. Try to initialize and check the candidate datasource (same logic as before)
            try:
                candidate_ds = ds_kls(self.sys_cfg, self.distro, self.paths)
                with util.SeededTimer(timeout=10.0, msg=f"check for {ds_name}") as t:
                    if candidate_ds.get_data():
                         LOG.info(f"MyFilteringProxy: Detected functional underlying datasource: '{ds_name}' after {t.msecs():.2f}ms")
                         detected_ds = candidate_ds
                         detected_ds_name = ds_name
                         break # Found the first working datasource
                    else:
                         LOG.debug(f"MyFilteringProxy: Datasource '{ds_name}' check returned False after {t.msecs():.2f}ms.")

            except sources.DataSourceNotFoundException:
                LOG.debug(f"MyFilteringProxy: Datasource '{ds_name}' not found/applicable in this environment.")
                continue
            except Exception as e:
                LOG.warning(f"MyFilteringProxy: Error initializing or checking datasource '{ds_name}': {e}")
                util.logexc(LOG, f"Datasource {ds_name} check failed")
                continue

        # 5. Store the result (same logic as before)
        if detected_ds:
            self.underlying_ds_instance = detected_ds
            self.underlying_ds_name = detected_ds_name
            self._initialized_underlying = True
            return True
        else:
            LOG.warning("MyFilteringProxy: No functional underlying datasource detected from the list.")
            self._initialized_underlying = True
            return False
        
    def _get_underlying_ds(self):
        """Ensures underlying DS is detected and returns the instance."""
        if not self._initialized_underlying:
            self._find_and_set_underlying_ds()
        return self.underlying_ds_instance

    # --- Filtering and Delegation Logic ---

    def get_data(self):
        """Fetch data, ensuring underlying DS is initialized."""
        # Ensure detection has run before trying to access underlying DS
        uds = self._get_underlying_ds()
        if not uds:
            LOG.warning("MyFilteringProxy: No underlying datasource detected, cannot get data.")
            return False
        # Let the underlying DS fetch its data. Our get_userdata_raw override
        # will handle the filtering when user-data is requested by core cloud-init.
        # The initial check was done during detection (_find_and_set_underlying_ds).
        # Re-calling uds.get_data() might be harmless or might re-fetch,
        # depending on the datasource's implementation. Returning True
        # assumes the initial check during detection was sufficient.
        # Alternatively, call it again if needed: return uds.get_data()
        return True # Indicate successful initialization/detection

    def get_userdata_raw(self):
        """Fetch raw user-data from the detected underlying source and filter it."""
        uds = self._get_underlying_ds()
        if not uds:
            LOG.warning("DataSourceBootHookFilter: No underlying datasource, cannot get user-data.")
            return None

        LOG.debug(f"DataSourceBootHookFilter: Requesting raw user-data from underlying datasource '{self.underlying_ds_name}'")
        try:
            original_userdata = uds.get_userdata_raw()
        except Exception as e:
            LOG.error(f"DataSourceBootHookFilter: Failed to get user-data from underlying DS: {e}")
            util.logexc(LOG, "Underlying get_userdata_raw failed")
            return None

        if original_userdata is None:
            LOG.debug("DataSourceBootHookFilter: Underlying datasource returned no user-data.")
            return None

        # Filter the fetched data
        filtered_userdata = filter_boothooks(original_userdata, LOG)

        # Update the underlying instance's cache. Some parts of cloud-init might access uds.userdata_raw directly.
        if hasattr(uds, 'userdata_raw'):
             uds.userdata_raw = filtered_userdata
             LOG.debug("DataSourceBootHookFilter: Updated underlying datasource's userdata_raw attribute.")

        return filtered_userdata

    # --- Delegate other essential DataSource methods ---
    # (Same delegation methods as before: platform, subplatform, get_instance_id, etc.)

    @property
    def platform(self):
        uds = self._get_underlying_ds()
        return uds.platform if uds else "proxy" # Indicate proxy if no underlying

    @property
    def subplatform(self):
        uds = self._get_underlying_ds()
        # Need to be careful about accessing _subplatform directly
        return getattr(uds, 'subplatform', 'filtered-proxy') if uds else "filtered-proxy"

    def get_instance_id(self):
        uds = self._get_underlying_ds()
        return uds.get_instance_id() if uds else "iid-proxy-unknown"

    def get_public_ssh_keys(self):
        uds = self._get_underlying_ds()
        return uds.get_public_ssh_keys() if uds else []

    def get_hostname(self, fqdn=False, metadata_only=False):
        # Delegate hostname fetching as well
        uds = self._get_underlying_ds()
        if uds and hasattr(uds, 'get_hostname'):
             return uds.get_hostname(fqdn=fqdn, metadata_only=metadata_only)
        # Provide a basic fallback if necessary
        return super(DataSourceBootHookFilter, self).get_hostname(fqdn=fqdn, metadata_only=metadata_only)

    def get_locale(self):
        uds = self._get_underlying_ds()
        return uds.get_locale() if uds else "en_US.UTF-8"

# Required function for cloud-init to discover this datasource
def get_datasource_list(depends):
    return [DataSourceBootHookFilter]
