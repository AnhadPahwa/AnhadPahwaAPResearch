SCENARIOS = {
    "valid": {"policy": "age_over_18"},
    "replay": {"policy": "age_over_18", "reuse_nonce": True},
    "revoked": {"policy": "age_over_18", "revoke": True},
    "policy_fail": {"policy": "age_over_16"}, 
    "cross_site": {"policy": "age_over_18", "domain_override": "other.com"}
}
