from dataclasses import dataclass


@dataclass(frozen=True)
class ReachabilityDecision:
    target: str
    primary_transport: str
    fallback_transport: str | None


def choose_reachability_path(target: str, is_local_target: bool) -> ReachabilityDecision:
    if is_local_target:
        return ReachabilityDecision(target=target, primary_transport="arp", fallback_transport="icmp")
    return ReachabilityDecision(target=target, primary_transport="icmp", fallback_transport=None)
