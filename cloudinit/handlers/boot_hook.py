# Copyright (C) 2012 Canonical Ltd.
# Copyright (C) 2012 Hewlett-Packard Development Company, L.P.
# Copyright (C) 2012 Yahoo! Inc.
#
# Author: Scott Moser <scott.moser@canonical.com>
# Author: Juerg Haefliger <juerg.haefliger@hp.com>
# Author: Joshua Harlow <harlowja@yahoo-inc.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging
import os

from cloudinit import handlers, subp, util
from cloudinit.settings import PER_ALWAYS

LOG = logging.getLogger(__name__)


class BootHookPartHandler(handlers.Handler):

    # The content prefixes this handler understands.
    prefixes = ["#cloud-boothook"]

    def __init__(self, paths, datasource, **_kwargs):
        handlers.Handler.__init__(self, PER_ALWAYS)
        self.boothook_dir = paths.get_ipath("boothooks")
        self.instance_id = None
        self.datasource = datasource
        if datasource:
            self.instance_id = datasource.get_instance_id()

    def _write_part(self, payload, filename):
        filename = util.clean_filename(filename)
        filepath = os.path.join(self.boothook_dir, filename)
        contents = util.strip_prefix_suffix(
            util.dos2unix(payload), prefix=self.prefixes[0]
        )
        util.write_file(filepath, contents.lstrip(), 0o700)
        return filepath

    def handle_part(self, data, ctype, filename, payload, frequency):
        if ctype in handlers.CONTENT_SIGNALS:
            return
        if not self._is_enabled():
            LOG.debug("Boothook handler is disabled")
            return

        filepath = self._write_part(payload, filename)
        try:
            env = (
                {"INSTANCE_ID": str(self.instance_id)}
                if self.instance_id
                else {}
            )
            LOG.debug("Executing boothook")
            subp.subp([filepath], update_env=env, capture=False)
        except subp.ProcessExecutionError:
            util.logexc(LOG, "Boothooks script %s execution error", filepath)
        except Exception:
            util.logexc(
                LOG, "Boothooks unknown error when running %s", filepath
            )

    def _is_enabled(self):
        is_enabled = True
        if self.datasource and hasattr(self.datasource, "sys_cfg"):
            handler_cfg = self.datasource.sys_cfg.get("handlers", {})
            if handler_cfg:
                LOG.debug("Boothook handler config found: %s", handler_cfg)
                is_enabled = handler_cfg.get("boothook_enabled", True)
            
        return is_enabled
