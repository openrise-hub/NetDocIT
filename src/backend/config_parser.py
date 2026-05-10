import ipaddress
import json
import os
from functools import lru_cache

from .safety_policy import ScopePolicy
from .runtime_paths import resource_path, runtime_path

def validate_config(config):
    errors = []
    
    # Validate subnet_tags CIDRs
    for subnet in config.get("subnet_tags", {}):
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            errors.append(f"Invalid subnet CIDR: {subnet}")
            
    return errors

@lru_cache(maxsize=1)
def load_config(config_path=None):
    """
    Loads the configuration.
    Returns an empty dictionary if the file is missing or unreadable.
    """
    candidate_paths = []
    if config_path is not None:
        candidate_paths.append(config_path)
    candidate_paths.extend([
        runtime_path("data", "config.json"),
        resource_path("data", "config.json"),
    ])
    
    for candidate in candidate_paths:
        if not os.path.exists(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    return {}


def load_scope_policy(config=None):
    policy = config.get("scope_policy", {}) if isinstance(config, dict) else {}
    return ScopePolicy(
        allow_subnets=frozenset(policy.get("allow_subnets", [])),
        deny_subnets=frozenset(policy.get("deny_subnets", [])),
        allow_hosts=frozenset(policy.get("allow_hosts", [])),
        deny_hosts=frozenset(policy.get("deny_hosts", [])),
        max_hosts=policy.get("max_hosts"),
        max_packets_per_second=policy.get("max_packets_per_second"),
        max_concurrency=policy.get("max_concurrency"),
    )

if __name__ == "__main__":
    print("Testing Supplemental Config Loader...")
    config = load_config()
    
    print("\nLoaded Credentials (SNMP):")
    print(config.get("credentials", {}).get("snmp", []))
    
    print("\nSubnet Tags Mapping:")
    print(config.get("subnet_tags", {}))
    
    print("\nScan Exclusions:")
    print(config.get("exclusions", []))
