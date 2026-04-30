from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopePolicy:
    allow_subnets: frozenset[str]
    deny_subnets: frozenset[str]
    allow_hosts: frozenset[str]
    deny_hosts: frozenset[str]
    max_hosts: int | None
    max_packets_per_second: int | None
    max_concurrency: int | None


@dataclass(frozen=True)
class ScopePolicyDecision:
    allowed: bool
    reason_code: str | None
    violations: list[str]
    effective_limits: dict[str, int | None]


def _effective_limits(policy: ScopePolicy) -> dict[str, int | None]:
    return {
        "max_hosts": policy.max_hosts,
        "max_packets_per_second": policy.max_packets_per_second,
        "max_concurrency": policy.max_concurrency,
    }


def evaluate_scope_policy(
    candidate_subnets: list[str],
    candidate_hosts: list[str],
    policy: ScopePolicy,
) -> ScopePolicyDecision:
    violations: list[str] = []

    if any(subnet in policy.deny_subnets for subnet in candidate_subnets):
        violations.append("subnet matched deny-list")
        return ScopePolicyDecision(False, "policy_denied_scope", violations, _effective_limits(policy))

    if policy.allow_subnets and any(subnet not in policy.allow_subnets for subnet in candidate_subnets):
        violations.append("subnet outside allowlist")
        return ScopePolicyDecision(False, "policy_denied_scope", violations, _effective_limits(policy))

    if any(host in policy.deny_hosts for host in candidate_hosts):
        violations.append("host matched deny-list")
        return ScopePolicyDecision(False, "policy_denied_scope", violations, _effective_limits(policy))

    if policy.allow_hosts and any(host not in policy.allow_hosts for host in candidate_hosts):
        violations.append("host outside allowlist")
        return ScopePolicyDecision(False, "policy_denied_scope", violations, _effective_limits(policy))

    if policy.max_hosts is not None and len(candidate_hosts) > policy.max_hosts:
        violations.append("candidate host count exceeded max_hosts")
        return ScopePolicyDecision(False, "policy_host_cap_exceeded", violations, _effective_limits(policy))

    return ScopePolicyDecision(True, None, [], _effective_limits(policy))


def policy_to_summary(policy: ScopePolicy) -> dict[str, object]:
    return {
        "allow_subnets": sorted(policy.allow_subnets),
        "deny_subnets": sorted(policy.deny_subnets),
        "allow_hosts": sorted(policy.allow_hosts),
        "deny_hosts": sorted(policy.deny_hosts),
        "max_hosts": policy.max_hosts,
        "max_packets_per_second": policy.max_packets_per_second,
        "max_concurrency": policy.max_concurrency,
    }


def decision_to_summary(decision: ScopePolicyDecision) -> dict[str, object]:
    return {
        "allowed": decision.allowed,
        "reason_code": decision.reason_code,
        "violations": list(decision.violations),
        "effective_limits": dict(decision.effective_limits),
    }