import unittest
import logging
import json
from allow_keys_filter import AllowKeyFilter

Base_CFG = """
{
  "datasource_list": [
    "Ec2",
    "None"
  ],
  "disable_boothook": true,
  "allow_keys": {
    "cloud_init_modules": "CONFIG",
    "cloud_config_modules": [
      "emit_upstart",
      "locale",
      "grub-dpkg",
      "timezone"
    ],
    "cloud_final_modules": "CUSTOM"
  },
  "cloud_init_modules": [
    "diskenc",
    "migrator",
    "ssh",
    "keysecure"
  ],
  "cloud_config_modules": [
    "emit_upstart",
    "locale",
    "grub-dpkg",
    "apt-pipelining",
    "apt-configure",
    "ntp",
    "timezone"
  ],
  "cloud_final_modules": [
    "rightscale_userdata",
    "scripts-vendor",
    "final_message",
    "power-state-change",
    "ntp"
  ],
  "hostname": "ciphertrust"
}
"""

class TestAllowKeyFilter(unittest.TestCase):
    def setUp(self) -> None:
        logging.basicConfig(level=logging.DEBUG) # Set the logging level
        self.logger = logging.getLogger(__name__)
        cfg = json.loads(Base_CFG)
        self.allow_key_filter = AllowKeyFilter(cfg)

    def test_gen_module_cfg_filter_config(self):
        cfg_k = "cloud_final_modules"
        cfg_v = "CONFIG"
        expected_keys = {
            "rightscale_userdata",
            "scripts-vendor",
            "final_message",
            "power-state-change",
            "ntp"
        }

        allow_keys = self.allow_key_filter._gen_module_cfg_filter(cfg_k, cfg_v)
        self.assertIsNotNone(allow_keys)
        self.assertSetEqual(expected_keys, set(allow_keys.keys()))

    def test_gen_module_cfg_filter_custom(self):
        cfg_k = "cloud_final_modules"
        cfg_v = "CUSTOM"
        expected_keys = {
            "rightscale_userdata",
            "scripts-vendor",
            "final_message",
            "power-state-change",
            "ntp",
            "cloud_final_modules"
        }

        allow_keys = self.allow_key_filter._gen_module_cfg_filter(cfg_k, cfg_v)
        self.assertIsNotNone(allow_keys)
        self.assertSetEqual(expected_keys, set(allow_keys.keys()))

    def test_gen_module_cfg_filter_list(self):
        cfg_k = "cloud_final_modules"
        cfg_v = [
            "rightscale_userdata",
            ["scripts-vendor", "once"],
            ["final_message", "always"],
            "power-state-change",
            "ntp"
        ]
        expected_keys = {
            "rightscale_userdata",
            "scripts-vendor",
            "final_message",
            "power-state-change",
            "ntp"
        }

        allow_keys = self.allow_key_filter._gen_module_cfg_filter(cfg_k, cfg_v)
        self.assertIsNotNone(allow_keys)
        self.assertSetEqual(expected_keys, set(allow_keys.keys()))

    def test_gen_key_list(self):
        cfg_allow_key_str = """
        {
            "cloud_init_modules": "CONFIG",
            "cloud_config_modules": [
              "emit_upstart",
              "locale",
              "grub-dpkg",
              "timezone"
            ],
            "cloud_final_modules": "CUSTOM"
          }
        """
        cfg_allow_keys = json.loads(cfg_allow_key_str)
        expected_keys = {
            "diskenc",
            "migrator",
            "ssh",
            "keysecure",
            "emit_upstart",
            "locale",
            "grub-dpkg",
            "timezone",
            "rightscale_userdata",
            "scripts-vendor",
            "final_message",
            "power-state-change",
            "ntp",
            "cloud_final_modules"
        }

        allow_keys = self.allow_key_filter._gen_key_list(cfg_allow_keys)
        self.assertIsNotNone(allow_keys)
        self.assertSetEqual(expected_keys, set(allow_keys.keys()))
    
    def test_gen_key_list_other(self):
        cfg_allow_key_str = """
        {
            "cloud_config_modules": [
              "emit_upstart",
              "locale",
              "grub-dpkg",
              "timezone"
            ],
            "output": ["init", "config", "final"]
          }
        """
        cfg_allow_keys = json.loads(cfg_allow_key_str)
        expected_keys = {
            "emit_upstart": None,
            "locale": None,
            "grub-dpkg": None,
            "timezone": None,
            "output": {
                "init": None,
                "config": None,
                "final": None
            } 
        }

        allow_keys = self.allow_key_filter._gen_key_list(cfg_allow_keys)
        self.assertIsNotNone(allow_keys)
        self.assertDictEqual(expected_keys, allow_keys)

    def test_do_filter(self):
        raw_cfg = json.loads("""
        {
          "cloud_final_modules": [["scripts-user", "always"]], 
          "final_message": "cloud-init has finished mmmm", 
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"],
          "output": {
            "init": "| tee -a /var/log/cloud-init-output.log",
            "all": "| tee -a /var/log/cloud-init-output.log"
          }
        }
        """)
        expected = json.loads("""
        {
          "final_message": "cloud-init has finished mmmm",
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"],
          "output": {
            "all": "| tee -a /var/log/cloud-init-output.log"
          }
        }
        """)
        allow_keys = {
            "locale": None,
            "scripts-vendor": None,
            "final_message": None,
            "power-state-change": None,
            "ntp": None,
            "runcmd": None,
            "output": {
              "all": None
            }
        }
        filtered = self.allow_key_filter._do_filter(raw_cfg, allow_keys)
        self.assertTrue(filtered == expected)

    def test_do_filter_negative(self):
        raw_cfg = json.loads("""
        {
          "cloud_final_modules": [["scripts-user", "always"]], 
          "final_message": "cloud-init has finished mmmm", 
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"],
          "output": {
            "init": "| tee -a /var/log/cloud-init-output.log",
            "all": "| tee -a /var/log/cloud-init-output.log"
          }
        }
        """)
        expected = json.loads("""
        {
          "final_message": "cloud-init has finished mmmm",
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"],
          "output": {
            "init": "| tee -a /var/log/cloud-init-output.log",
            "all": "| tee -a /var/log/cloud-init-output.log"
          }
        }
        """)
        allow_keys = {
            "locale": None,
            "scripts-vendor": None,
            "final_message": None,
            "power-state-change": None,
            "ntp": None,
            "runcmd": None,
            "output": {
              "all": None
            }
        }
        filtered = self.allow_key_filter._do_filter(raw_cfg, allow_keys)
        self.assertFalse(filtered == expected)

    def test_filter(self):
        raw_cfg = json.loads("""
        {
          "cloud_final_modules": [["scripts-user", "always"]], 
          "final_message": "cloud-init has finished mmmm", 
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"]
        }
        """)
        expected = json.loads("""
        {
          "cloud_final_modules": [["scripts-user", "always"]], 
          "final_message": "cloud-init has finished mmmm"
        }
        """)
        filtered = self.allow_key_filter.filter(raw_cfg)
        self.assertDictEqual(filtered, expected)
        
    def test_filter_negative(self):
        raw_cfg = json.loads("""
        {
          "cloud_final_modules": [["scripts-user", "always"]], 
          "final_message": "cloud-init has finished mmmm", 
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"]
        }
        """)
        expected = json.loads("""
        {
          "cloud_final_modules": [["scripts-user", "always"]], 
          "final_message": "cloud-init has finished mmmm", 
          "runcmd": ["echo 'Run runcmd script' > /var/log/runcmd.txt"]
        }
        """)
        filtered = self.allow_key_filter.filter(raw_cfg)
        self.assertNotEqual(filtered, expected)

if __name__ == '__main__':
    unittest.main()

