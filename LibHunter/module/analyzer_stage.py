from __future__ import annotations

import json
import os
from typing import Dict, List, Sequence, Set, Tuple

from packaging.version import InvalidVersion, Version


DEFAULT_PROBE_MAX_THRESHOLD = 0.5
DEFAULT_PROBE_MEAN_THRESHOLD = 0.35
DEFAULT_PROBE_COUNT = 3
DEFAULT_PROBE_PICK_STRATEGY = "old_mid_new"


def _probe_config_from_env() -> dict:
    max_th = float(os.environ.get("LH_PROBE_MAX_THRESHOLD", str(DEFAULT_PROBE_MAX_THRESHOLD)))
    mean_th = float(os.environ.get("LH_PROBE_MEAN_THRESHOLD", str(DEFAULT_PROBE_MEAN_THRESHOLD)))
    probe_count = int(os.environ.get("LH_PROBE_COUNT", str(DEFAULT_PROBE_COUNT)))
    probe_count = max(1, probe_count)
    strategy = (os.environ.get("LH_PROBE_PICK_STRATEGY", DEFAULT_PROBE_PICK_STRATEGY) or "").strip().lower()
    if strategy not in {"old_mid_new", "old-middle-new"}:
        strategy = "old_mid_new"
    fallback_mode = (os.environ.get("LH_PROBE_EMPTY_FALLBACK", "all") or "").strip().lower()
    if fallback_mode not in {"all", "none"}:
        fallback_mode = "all"
    return {
        "max_threshold": max_th,
        "mean_threshold": mean_th,
        "probe_count": probe_count,
        "strategy": strategy,
        "fallback_mode": fallback_mode,
    }


def _probe_version_sort_key(path: str):
    filename = os.path.basename(path)
    stem = filename[:-4] if filename.endswith(".dex") else filename
    version = stem.split("_", 1)[-1] if "_" in stem else stem
    normalized = version.replace("_", ".").strip()
    try:
        return (0, Version(normalized), normalized)
    except InvalidVersion:
        return (1, normalized.lower(), normalized)


def _select_probe_versions(versions: Sequence[str], probe_count: int = 3) -> Dict[str, str]:
    if not versions:
        return {}
    ordered = sorted(set(versions), key=_probe_version_sort_key)
    if len(ordered) == 1:
        return {"old": ordered[0], "mid": ordered[0], "new": ordered[0]}

    idxs = [0, len(ordered) // 2, len(ordered) - 1]
    labels = ["old", "mid", "new"]
    selected: Dict[str, str] = {}
    for label, idx in zip(labels, idxs):
        selected[label] = ordered[idx]

    _ = probe_count
    return selected


def _admit_family_from_probe_matches(
    probe_matches: Dict[str, bool],
) -> Tuple[bool, str, int]:
    matched_count = sum(1 for matched in probe_matches.values() if matched)
    if matched_count > 0:
        return True, "any_probe_matched", matched_count
    return False, "no_probe_matched", 0


def _run_stage1_probe_discovery(
    apk_obj,
    lib_groups: Dict[str, List[str]],
    load_lib_obj,
    logger,
    detect_func=None,
) -> dict:
    if detect_func is None:
        from analyzer import detect as detect_func  # lazy import to avoid import cycle at module load

    cfg = _probe_config_from_env()
    families = sorted(lib_groups.keys())
    admitted_map: Dict[str, dict] = {}
    family_scores: Dict[str, dict] = {}

    for family in families:
        versions = lib_groups.get(family, [])
        probes = _select_probe_versions(versions, cfg["probe_count"])
        probe_scores: Dict[str, float] = {}
        probe_matches: Dict[str, bool] = {}
        probe_targets: Set[str] = set()

        for probe_tag, rel_version in probes.items():
            lib_obj = load_lib_obj(rel_version)
            if lib_obj is None:
                probe_scores[probe_tag] = 0.0
                probe_matches[probe_tag] = False
                continue
            detail = detect_func(apk_obj, lib_obj, logger, return_details=True)
            score = float(detail.get("score", 0.0))
            probe_scores[probe_tag] = score
            probe_matches[probe_tag] = bool(detail.get("matched", False))
            for cls in detail.get("target_classes", []) or []:
                cls_text = str(cls).strip()
                if cls_text:
                    probe_targets.add(cls_text)

        values = [float(v) for v in probe_scores.values()]
        max_score = max(values) if values else 0.0
        mean_score = (sum(values) / float(len(values))) if values else 0.0
        admitted, rule, matched_count = _admit_family_from_probe_matches(probe_matches)
        family_scores[family] = {
            "probe_versions": probes,
            "probe_scores": probe_scores,
            "probe_matches": probe_matches,
            "max_probe_score": max_score,
            "mean_probe_score": mean_score,
            "matched_probe_count": matched_count,
            "admitted": admitted,
            "admission_rule": rule,
            "probe_target_classes": sorted(probe_targets),
        }
        if admitted:
            admitted_map[family] = family_scores[family]

        # Per-family probe summary for stage1 observability.
        logger.info(
            "[libhunter] stage1_probe_family family=%s mean=%.4f max=%.4f matched=%d admitted=%s rule=%s scores=%s matches=%s",
            family,
            mean_score,
            max_score,
            matched_count,
            admitted,
            rule,
            probe_scores,
            probe_matches,
        )

    fallback_triggered = False
    admitted_families = sorted(admitted_map.keys())
    if not admitted_families and cfg["fallback_mode"] == "all":
        fallback_triggered = True
        admitted_families = families
        for family in families:
            base = family_scores.setdefault(family, {})
            base.setdefault("probe_versions", _select_probe_versions(lib_groups.get(family, []), cfg["probe_count"]))
            base.setdefault("probe_scores", {})
            base["admitted"] = True
            base["admission_rule"] = "fallback_all"
            admitted_map[family] = base

    total_families = len(families)
    candidate_count = len(admitted_families)
    reduction_ratio = 0.0 if total_families == 0 else 1.0 - (candidate_count / float(total_families))

    logger.info(
        "[libhunter] stage1_probe total=%d admitted=%d reduction=%.2f%% fallback=%s",
        total_families,
        candidate_count,
        reduction_ratio * 100.0,
        fallback_triggered,
    )
    if reduction_ratio < 0.90:
        logger.warning(
            "[libhunter] stage1_probe reduction below 90%% target: %.2f%%",
            reduction_ratio * 100.0,
        )

    return {
        "config": cfg,
        "family_scores": family_scores,
        "admitted_map": admitted_map,
        "admitted_families": admitted_families,
        "total_families": total_families,
        "candidate_families": candidate_count,
        "candidate_reduction_ratio": reduction_ratio,
        "fallback_triggered": fallback_triggered,
    }


def _aggregate_stage2_peaks(version_details: List[dict], stage1: dict) -> dict:
    by_family: Dict[str, List[dict]] = {}
    for row in version_details:
        family = str(row.get("library_family", "")).strip()
        if not family:
            continue
        by_family.setdefault(family, []).append(row)

    family_scores = stage1.get("family_scores", {})
    peaks: List[dict] = []
    detections: List[dict] = []
    for family, rows in by_family.items():
        best = max(rows, key=lambda item: float(item.get("similarity", 0.0)))
        meta = family_scores.get(family, {})
        peak = {
            "library_family": family,
            "selected_version": best.get("selected_version", ""),
            "lib": best.get("lib", ""),
            "similarity": float(best.get("similarity", 0.0)),
            "matched": bool(best.get("matched", False)),
            "target_classes": list(best.get("target_classes", [])),
            "probe_scores": meta.get("probe_scores", {}),
            "admission_rule": meta.get("admission_rule", ""),
        }
        peaks.append(peak)
        if peak["matched"]:
            detections.append(peak)

    peaks.sort(key=lambda item: item["similarity"], reverse=True)
    detections.sort(key=lambda item: item["similarity"], reverse=True)
    return {
        "peaks": peaks,
        "detections": detections,
    }


def _write_libhunter_reports(
    *,
    output_folder: str,
    apk_name: str,
    stage1: dict,
    stage2: dict,
    apk_time_seconds: int,
) -> None:
    txt_path = os.path.join(output_folder, apk_name + ".txt")
    with open(txt_path, "w", encoding="utf-8") as result:
        for det in stage2.get("detections", []):
            result.write("lib: " + str(det.get("lib", "")) + "\n")
            result.write("similarity: " + str(det.get("similarity", 0.0)) + "\n")
            target_classes = list(det.get("target_classes", []))
            if target_classes:
                result.write("Class Names/Packages: [" + ", ".join(target_classes) + "]\n")
            result.write("\n")
        result.write("time: " + str(apk_time_seconds) + "s")

    json_path = os.path.join(output_folder, apk_name + ".json")
    payload = {
        "apk": apk_name,
        "stage1": {
            "max_threshold": stage1.get("config", {}).get("max_threshold", DEFAULT_PROBE_MAX_THRESHOLD),
            "mean_threshold": stage1.get("config", {}).get("mean_threshold", DEFAULT_PROBE_MEAN_THRESHOLD),
            "total_families": stage1.get("total_families", 0),
            "candidate_families": stage1.get("candidate_families", 0),
            "candidate_reduction_ratio": stage1.get("candidate_reduction_ratio", 0.0),
            "fallback_triggered": stage1.get("fallback_triggered", False),
        },
        "detections": stage2.get("detections", []),
        "stage2_peaks": stage2.get("peaks", []),
        "time_seconds": apk_time_seconds,
    }
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
