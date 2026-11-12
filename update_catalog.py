#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refresh catalog.json from Google's public Pixel build pages.

Canary builds come from the Flash Station API, and the newest stable
build for each codename comes from the same API. Device order, marketing
names, and launch SDK levels are read from catalog.json and written back
unchanged. A run that learns nothing leaves the existing catalog alone.
"""

import email.utils
import html
import http.client
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

GOOGLE_URL = "https://developer.android.com"
FLASH_URL = "https://flash.android.com"
# First letter of a current Pixel build id. The factory-images HTML page no
# longer contains the device tables, so the Android release comes from this.
MAJOR_BY_PREFIX = {"A": "15", "B": "16", "C": "17", "D": "18"}
CATALOG_PATH = Path(__file__).with_name("catalog.json")
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Filled from catalog.json by load_table(). The file is the source of these lists.
DEVICE_MODEL_MAP = {}
PICKER_ORDER = []
GENERATION_ORDER = []
INITIAL_SDK = {}
DEFAULT_CODENAME = ""
DEFAULT_INITIAL_SDK = "32"
TABLET_CODENAME = ""
TABLE_KEYS = (
    "models",
    "picker_order",
    "generation_order",
    "initial_sdk",
    "default_codename",
    "default_initial_sdk",
    "tablet_codename",
)

class RateLimited(Exception):
    pass


def read_url(url, extra_headers=None, timeout=20):
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en",
    }
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def read_url_retry(url, extra_headers=None, timeout=20):
    try:
        return read_url(url, extra_headers, timeout)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as first:
        print(f"retry {url}: {first}", file=sys.stderr)
        return read_url(url, extra_headers, timeout)


def patch_from_build_id(build_id):
    match = re.search(r"\.(\d{2})(0[1-9]|1[0-2])\d{2}\.", build_id)
    if not match:
        return "2026-05-05"
    return f"20{match.group(1)}-{match.group(2)}-05"


def security_patch_from_build_id(build_id):
    first = build_id.find(".")
    second = build_id.find(".", first + 1) if first >= 0 else -1
    if first < 0 or second != first + 7:
        return patch_from_build_id(build_id)
    yymmdd = build_id[first + 1:second]
    if len(yymmdd) != 6 or not yymmdd.isdigit():
        return patch_from_build_id(build_id)
    month = int(yymmdd[2:4])
    day = int(yymmdd[4:6])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return patch_from_build_id(build_id)
    return f"20{yymmdd[:2]}-{yymmdd[2:4]}-{yymmdd[4:6]}"


def model_name(device, scraped):
    if scraped:
        return scraped
    return DEVICE_MODEL_MAP.get(device, f"Unknown Pixel ({device})")


def fetch_last_modified(url):
    if not url:
        return None
    current = url
    try:
        for _ in range(5):
            parsed = urlparse(current)
            if parsed.scheme != "https" or not parsed.netloc:
                return None
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            connection = http.client.HTTPSConnection(parsed.netloc, timeout=8)
            try:
                connection.request("HEAD", path, headers={"User-Agent": UA})
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location:
                        return None
                    current = urllib.request.urljoin(current, location)
                    continue
                last_modified = response.getheader("Last-Modified")
            finally:
                connection.close()
            if not last_modified:
                return None
            parsed_date = email.utils.parsedate_to_datetime(last_modified)
            return parsed_date.date().isoformat()
    except (OSError, http.client.HTTPException, ValueError, TypeError) as error:
        print(f"release date unavailable: {error}", file=sys.stderr)
    return None


def profile(device, model, product, fingerprint, build_id, security_patch,
            release_date, is_canary):
    return {
        "codename": device,
        "model": model,
        "brand": "google",
        "device": device,
        "product": product,
        "fingerprint": fingerprint,
        "buildId": build_id,
        "securityPatch": security_patch,
        "releaseDate": release_date,
        "isCanary": is_canary,
        "initialSdk": INITIAL_SDK.get(device, DEFAULT_INITIAL_SDK),
    }


def sort_profiles(profiles):
    rank = {codename: index for index, codename in enumerate(PICKER_ORDER)}
    return sorted(profiles, key=lambda item: (rank.get(item["codename"], len(rank)), item["codename"]))


def find_api_key(page_html):
    match = re.search(r"AIza[0-9A-Za-z_-]{35}", page_html)
    if match:
        return match.group(0)
    for src in re.findall(r'<script[^>]+src="([^"]+)"', page_html)[:8]:
        script_url = urllib.request.urljoin(FLASH_URL + "/", src)
        if urlparse(script_url).netloc != urlparse(FLASH_URL).netloc:
            continue
        try:
            script = read_url(script_url, timeout=20)
        except (urllib.error.URLError, TimeoutError) as error:
            print(f"flash script skipped: {error}", file=sys.stderr)
            continue
        match = re.search(r"AIza[0-9A-Za-z_-]{35}", script)
        if match:
            return match.group(0)
    return None


def canary_from_builds(device, builds_json, scraped_name):
    if not builds_json.lstrip().startswith("{"):
        raise RateLimited(device)
    root = json.loads(builds_json)
    builds = root.get("flashstationBuild") or []
    chosen = None
    best_rank = -1
    for build in builds:
        if not isinstance(build, dict):
            continue
        meta = build.get("previewMetadata") or {}
        if not meta.get("canary"):
            continue
        release_name = build.get("releaseCandidateName") or ""
        build_id = str(build.get("buildId") or "")
        if not release_name or not build_id:
            continue
        try:
            rank = int(build_id)
        except ValueError:
            rank = 0
        if rank <= best_rank:
            continue
        best_rank = rank
        image_url = build.get("factoryImageDownloadUrl") or meta.get("factoryImageDownloadUrl") or ""
        mid = meta.get("id") or ""
        chosen = (release_name, build_id, mid if "canary-" in mid else None, image_url or None)
    if chosen is None:
        return None
    release_name, incremental, canary_id, image_url = chosen
    security_patch = patch_from_build_id(release_name)
    if canary_id:
        month = re.search(r"canary-(\d{4})(\d{2})", canary_id)
        if month:
            security_patch = f"{month.group(1)}-{month.group(2)}-05"
    product = f"{device}_beta"
    fingerprint = (
        f"google/{product}/{device}:CANARY/{release_name}/{incremental}:user/release-keys"
    )
    return {
        "pending_url": image_url,
        "profile": profile(
            device,
            model_name(device, scraped_name),
            product,
            fingerprint,
            release_name,
            security_patch,
            None,
            True,
        ),
    }


def fetch_builds(api_key, product):
    url = (
        "https://content-flashstation-pa.googleapis.com/v1/builds"
        f"?product={product}&key={api_key}"
    )
    body = read_url(
        url,
        extra_headers={"Referer": FLASH_URL, "X-Goog-Api-Key": api_key},
        timeout=20,
    )
    if not body.lstrip().startswith("{"):
        raise RateLimited(product)
    root = json.loads(body)
    builds = root.get("flashstationBuild") or []
    return [build for build in builds if isinstance(build, dict)]


def newest_stable_build(builds):
    chosen = None
    best_rank = -1
    for build in builds:
        meta = build.get("previewMetadata") or {}
        if meta.get("canary") or meta.get("releaseTrackName"):
            continue
        release_name = build.get("releaseCandidateName") or ""
        build_id = str(build.get("buildId") or "")
        if not release_name or not build_id:
            continue
        try:
            rank = int(build_id)
        except ValueError:
            rank = 0
        if rank <= best_rank:
            continue
        best_rank = rank
        chosen = build
    return chosen


def stable_from_build(device, build, scraped_name):
    release_name = build.get("releaseCandidateName") or ""
    incremental = str(build.get("buildId") or "")
    major = MAJOR_BY_PREFIX.get(release_name[:1].upper())
    if not major:
        print(f"unknown android major for {device} {release_name}", file=sys.stderr)
        return None
    fingerprint = (
        f"google/{device}/{device}:{major}/{release_name}/{incremental}:user/release-keys"
    )
    image_url = build.get("factoryImageDownloadUrl") or None
    return {
        "pending_url": image_url,
        "profile": profile(
            device,
            model_name(device, scraped_name),
            device,
            fingerprint,
            release_name,
            security_patch_from_build_id(release_name),
            None,
            False,
        ),
    }


def device_codenames(ota_html, factory_html):
    names = {}
    devices = []
    seen = set()
    row = re.compile(r'<tr id="([^"]+)">\s*<td[^>]*>([^<]*)</td>', re.DOTALL)
    for source in (ota_html, factory_html):
        for match in row.finditer(source):
            device = match.group(1).strip()
            model = html.unescape(match.group(2)).strip()
            if device not in seen:
                seen.add(device)
                devices.append(device)
            if model and device not in names:
                names[device] = model
    return devices, names


def fetch_canary():
    versions_html = read_url_retry(GOOGLE_URL + "/about/versions", timeout=30)
    known = []
    seen_versions = set()
    for match in re.finditer(r"https://developer\.android\.com/about/versions/(\d+)", versions_html):
        version = int(match.group(1))
        if version not in seen_versions:
            seen_versions.add(version)
            known.append(version)
    if not known:
        return [], True, [], {}, []
    known.sort(reverse=True)
    versions = [known[0] + 1, *known]
    qpr_pattern = re.compile(r'href="(/about/versions/\d+/qpr(\d+)/download-ota)"')
    flash_html = read_url_retry(FLASH_URL, timeout=30)
    api_key = find_api_key(flash_html)
    if not api_key:
        print("flash.android.com API key not found", file=sys.stderr)
        return [], True, [], {}, []

    for version in versions:
        try:
            latest_html = read_url_retry(f"{GOOGLE_URL}/about/versions/{version}", timeout=30)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as error:
            print(f"version {version} skipped: {error}", file=sys.stderr)
            continue
        best_qpr = -1
        best_path = None
        for match in qpr_pattern.finditer(latest_html):
            qpr_num = int(match.group(2))
            if qpr_num > best_qpr:
                best_qpr = qpr_num
                best_path = match.group(1)
        if best_path is None:
            continue
        try:
            ota_html = read_url_retry(GOOGLE_URL + best_path, timeout=30)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as error:
            print(f"OTA page skipped: {error}", file=sys.stderr)
            continue
        factory_path = best_path.replace("/download-ota", "/download")
        try:
            factory_html = read_url_retry(GOOGLE_URL + factory_path, timeout=30)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as error:
            print(f"factory page skipped: {error}", file=sys.stderr)
            factory_html = ""
        devices, scraped_names = device_codenames(ota_html, factory_html)
        if not devices:
            continue

        pending = []
        no_canary = []
        stopped = False
        for device in devices:
            product = f"{device}_beta"
            url = (
                "https://content-flashstation-pa.googleapis.com/v1/builds"
                f"?product={product}&key={api_key}"
            )
            try:
                body = read_url(
                    url,
                    extra_headers={
                        "Referer": FLASH_URL,
                        "X-Goog-Api-Key": api_key,
                    },
                    timeout=20,
                )
                built = canary_from_builds(device, body, scraped_names.get(device))
            except RateLimited:
                print(f"flashstation rate-limited at {product}, stopping crawl", file=sys.stderr)
                stopped = True
                break
            except urllib.error.HTTPError as error:
                print(f"canary fetch failed for {device}: HTTP {error.code}", file=sys.stderr)
                if error.code in (403, 429):
                    stopped = True
                    break
                continue
            except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError):
                print(f"canary fetch failed for {device}", file=sys.stderr)
                continue
            if built is None:
                no_canary.append(device)
                continue
            pending.append(built)

        profiles = with_release_dates(pending)
        if profiles or no_canary:
            return profiles, stopped, devices, scraped_names, no_canary
    return [], True, [], {}, []


def with_release_dates(pending):
    urls = [item["pending_url"] for item in pending]
    with ThreadPoolExecutor(max_workers=6) as pool:
        dates = list(pool.map(fetch_last_modified, urls))
    profiles = []
    for item, release_date in zip(pending, dates):
        if release_date:
            item["profile"]["releaseDate"] = release_date
        profiles.append(item["profile"])
    return profiles


def fetch_stable(qpr_devices, names):
    flash_html = read_url_retry(FLASH_URL, timeout=30)
    api_key = find_api_key(flash_html)
    if not api_key:
        print("flash.android.com API key not found", file=sys.stderr)
        return [], True
    devices = list(qpr_devices)
    seen = set(qpr_devices)
    for codename in DEVICE_MODEL_MAP:
        if codename not in seen:
            devices.append(codename)
            seen.add(codename)
    pending = []
    stopped = False
    for device in devices:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", device):
            continue
        try:
            builds = fetch_builds(api_key, device)
        except RateLimited:
            print(f"flashstation rate-limited at {device}, stopping stable crawl", file=sys.stderr)
            stopped = True
            break
        except urllib.error.HTTPError as error:
            if error.code in (403, 429):
                print(f"stable fetch stopped at {device}: HTTP {error.code}", file=sys.stderr)
                stopped = True
                break
            continue
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, json.JSONDecodeError):
            print(f"stable fetch failed for {device}", file=sys.stderr)
            continue
        build = newest_stable_build(builds)
        if build is None:
            continue
        built = stable_from_build(device, build, names.get(device))
        if built is not None:
            pending.append(built)
    return with_release_dates(pending), stopped


def default_codename(profiles):
    present = {item["codename"] for item in profiles}
    if DEFAULT_CODENAME in present:
        return DEFAULT_CODENAME
    for codename in GENERATION_ORDER:
        if codename in present:
            return codename
    if profiles:
        return profiles[0]["codename"]
    return DEFAULT_CODENAME


def load_existing():
    if not CATALOG_PATH.is_file():
        return None
    try:
        return json.loads(CATALOG_PATH.read_text())
    except json.JSONDecodeError as error:
        print(f"existing catalog is unreadable: {error}", file=sys.stderr)
        return None


def load_table(existing):
    global DEVICE_MODEL_MAP, PICKER_ORDER, GENERATION_ORDER, INITIAL_SDK
    global DEFAULT_CODENAME, DEFAULT_INITIAL_SDK, TABLET_CODENAME
    if not isinstance(existing, dict):
        raise SystemExit("catalog.json is missing")
    missing = [key for key in TABLE_KEYS if key not in existing]
    if missing:
        raise SystemExit("catalog.json is missing " + ", ".join(missing))
    DEVICE_MODEL_MAP = existing["models"]
    PICKER_ORDER = list(existing["picker_order"])
    GENERATION_ORDER = list(existing["generation_order"])
    INITIAL_SDK = existing["initial_sdk"]
    DEFAULT_CODENAME = existing["default_codename"]
    DEFAULT_INITIAL_SDK = str(existing["default_initial_sdk"])
    TABLET_CODENAME = existing["tablet_codename"]


def merge_profiles(fresh, previous, stopped_early):
    if not stopped_early or not previous:
        return fresh
    fresh_names = {item["codename"] for item in fresh}
    kept = [item for item in previous if item.get("codename") not in fresh_names]
    if kept:
        print(f"kept {len(kept)} previous profiles after a partial crawl", file=sys.stderr)
    return fresh + kept


def comparable(document):
    return json.dumps(
        {
            "default_codename": document.get("default_codename"),
            "profiles": document.get("profiles"),
            "stable": document.get("stable"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def main():
    existing = load_existing()
    load_table(existing)
    previous_profiles = (existing or {}).get("profiles") or []
    previous_stable = (existing or {}).get("stable") or []

    try:
        canary, stopped, qpr_devices, names, no_canary = fetch_canary()
    except (urllib.error.URLError, TimeoutError, ssl.SSLError):
        print("canary crawl failed", file=sys.stderr)
        canary, stopped, qpr_devices, names, no_canary = [], True, [], {}, []
    try:
        stable, stable_stopped = fetch_stable(qpr_devices, names)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError):
        print("stable crawl failed", file=sys.stderr)
        stable, stable_stopped = [], True

    have = {item["codename"] for item in canary}
    for item in stable:
        if item["codename"] in no_canary and item["codename"] not in have:
            canary.append(item)
            have.add(item["codename"])

    profiles = merge_profiles(canary, previous_profiles, stopped or not canary)
    stable = merge_profiles(stable, previous_stable, stable_stopped or not stable)
    if not profiles and not stable:
        print("catalog refresh produced nothing", file=sys.stderr)
        return 1

    document = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "default_codename": default_codename(profiles or stable),
        "default_initial_sdk": DEFAULT_INITIAL_SDK,
        "tablet_codename": TABLET_CODENAME,
        "generation_order": GENERATION_ORDER,
        "picker_order": PICKER_ORDER,
        "models": DEVICE_MODEL_MAP,
        "initial_sdk": INITIAL_SDK,
        "profiles": sort_profiles(profiles),
        "stable": sort_profiles(stable),
    }
    if existing is not None and comparable(existing) == comparable(document):
        print(
            f"unchanged ({len(document['profiles'])} profiles, "
            f"{len(document['stable'])} stable)"
        )
        return 0
    text = json.dumps(document, indent=2) + "\n"
    CATALOG_PATH.write_text(text)
    print(
        f"wrote {CATALOG_PATH.name}: {len(document['profiles'])} profiles, "
        f"{len(document['stable'])} stable, default {document['default_codename']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
