"""Placeholder for future stateful flow tracking (5-tuple session correlation).

Not yet implemented. Intended to eventually group individual packets into
bidirectional flows (src_ip, dst_ip, src_port, dst_port, protocol) so
detections can reason about session-level behavior instead of raw packet
counts. Left as an explicit stub, rather than removed, to mark it as a
planned extension point.
"""

from __future__ import annotations
