"""Phase 5 — location / time risk: impossible travel, outside hours, geo risk."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Tuple


def _approx_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import radians, cos, sqrt
    x = radians(lon2 - lon1) * cos(radians((lat1 + lat2) / 2))
    y = radians(lat2 - lat1)
    return 6371.0 * sqrt(x * x + y * y)


@dataclass
class LocationPoint:
    lat: float
    lon: float
    ts: datetime
    ip: Optional[str] = None
    label: Optional[str] = None


def parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def impossible_travel(
    prev: LocationPoint,
    curr: LocationPoint,
    max_speed_kmh: float = 900.0,
) -> Tuple[bool, dict]:
    hours = abs((curr.ts - prev.ts).total_seconds()) / 3600.0
    if hours <= 0:
        hours = 1e-6
    km = _approx_km(prev.lat, prev.lon, curr.lat, curr.lon)
    speed = km / hours
    flag = speed > max_speed_kmh
    return flag, {
        "distance_km": round(km, 1),
        "hours": round(hours, 3),
        "implied_kmh": round(speed, 1),
        "max_speed_kmh": max_speed_kmh,
        "prev": {"lat": prev.lat, "lon": prev.lon, "ip": prev.ip},
        "curr": {"lat": curr.lat, "lon": curr.lon, "ip": curr.ip},
    }


def outside_hours(
    now: datetime,
    start_hour: int = 9,
    end_hour: int = 18,
    weekdays_only: bool = True,
) -> Tuple[bool, dict]:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    weekday = now.weekday()
    hour = now.hour
    weekend = weekday >= 5
    if weekdays_only and weekend:
        return True, {"reason": "weekend", "hour": hour, "weekday": weekday}
    if hour < start_hour or hour >= end_hour:
        return True, {
            "reason": "outside_window",
            "hour": hour,
            "window": [start_hour, end_hour],
            "weekday": weekday,
        }
    return False, {"reason": "inside_window", "hour": hour, "weekday": weekday}


def geo_risk(
    country_code: Optional[str],
    allow_list: Optional[list] = None,
    deny_list: Optional[list] = None,
) -> Tuple[bool, dict]:
    allow_list = allow_list or []
    deny_list = deny_list or []
    if not country_code:
        return False, {"country": None, "risk": "unknown"}
    cc = country_code.upper()
    if deny_list and cc in [x.upper() for x in deny_list]:
        return True, {"country": cc, "risk": "deny_list"}
    if allow_list and cc not in [x.upper() for x in allow_list]:
        return True, {"country": cc, "risk": "not_in_allow_list"}
    return False, {"country": cc, "risk": "ok"}


def enrich_event_location(
    event: dict,
    *,
    impossible: bool = False,
    travel_detail: Optional[dict] = None,
    outside: bool = False,
    hours_detail: Optional[dict] = None,
    geo_flag: bool = False,
    geo_detail: Optional[dict] = None,
) -> dict:
    out = dict(event)
    attrs = dict(out.get("attrs") or {})
    if impossible:
        attrs["impossible_travel"] = True
        if travel_detail:
            attrs["travel_detail"] = travel_detail
    if outside:
        attrs["outside_hours"] = True
        attrs["location_violation"] = True
        if hours_detail:
            attrs["hours_detail"] = hours_detail
    if geo_flag:
        attrs["geo_risk"] = True
        attrs["location_violation"] = True
        if geo_detail:
            attrs["geo_detail"] = geo_detail
    out["attrs"] = attrs
    return out
