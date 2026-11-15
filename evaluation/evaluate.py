"""Evaluate CloudGuard findings against explicitly labelled ground truth.

Ground-truth CSV schema:
    resource_type,resource_id,rule_id,expected

Finding CSVs must contain the same resource_type/resource_id pair. Matching
is exact and case-sensitive; display names and partial identifiers are never
used as substitutes for resource identity.

Usage:
    python evaluation/evaluate.py evaluation/ground_truth_template.csv findings.csv
"""
import csv
import sys


REQUIRED_GROUND_TRUTH_FIELDS = ("resource_type", "resource_id", "rule_id", "expected")
REQUIRED_FINDING_FIELDS = ("resource_type", "resource_id")
VALID_EXPECTATIONS = {"PASS", "FAIL"}


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as file_handle:
        return list(csv.DictReader(file_handle))


def _normalized_required(row, field, row_number):
    value = row.get(field)
    if value is None or not str(value).strip():
        raise ValueError(f"Ground-truth row {row_number}: {field!r} must not be empty")
    return str(value).strip()


def validate_ground_truth(ground_truth):
    """Reject incomplete, unsupported, or duplicate ground-truth records."""
    seen = set()
    normalized = []
    for row_number, row in enumerate(ground_truth, start=2):
        record = {
            field: _normalized_required(row, field, row_number)
            for field in REQUIRED_GROUND_TRUTH_FIELDS
            if field != "expected"
        }
        expected_value = row.get("expected")
        expected = str(expected_value).strip().upper() if expected_value is not None else ""
        if expected not in VALID_EXPECTATIONS:
            raise ValueError(
                f"Ground-truth row {row_number}: expected must be PASS or FAIL, "
                f"not {expected_value!r}"
            )
        record["expected"] = expected
        # Resource type + exact identifier + rule is one unique test case.
        key = (record["resource_type"], record["resource_id"], record["rule_id"])
        if key in seen:
            raise ValueError(
                f"Ground-truth row {row_number}: duplicate record for "
                f"resource_type={key[0]!r}, resource_id={key[1]!r}, rule_id={key[2]!r}"
            )
        seen.add(key)
        normalized.append(record)
    return normalized


def validate_findings(findings):
    """Ensure finding input carries explicit resource identity fields."""
    normalized = []
    for index, finding in enumerate(findings, start=1):
        missing = [field for field in REQUIRED_FINDING_FIELDS
                   if finding.get(field) is None or not str(finding.get(field)).strip()]
        if missing:
            raise ValueError(
                f"Finding row {index}: missing required field(s): {', '.join(missing)}"
            )
        normalized.append({
            **finding,
            "resource_type": str(finding["resource_type"]).strip(),
            "resource_id": str(finding["resource_id"]).strip(),
            # Unmapped scanner checks intentionally have no rule_id. Keep
            # them as unlabelled findings rather than rejecting the whole CSV.
            "rule_id": str(finding.get("rule_id") or "").strip(),
        })
    return normalized


def matches(gt_row, finding):
    """Match only when rule, resource type, and identifier are all identical."""
    return (
        str(finding.get("rule_id", "")).strip() == gt_row["rule_id"]
        and str(finding.get("resource_type", "")).strip() == gt_row["resource_type"]
        and str(finding.get("resource_id", "")).strip() == gt_row["resource_id"]
    )


def evaluate(ground_truth, findings):
    ground_truth = validate_ground_truth(ground_truth)
    findings = validate_findings(findings)

    tp = fp = fn = tn = 0
    detail = []
    used = set()
    for row in ground_truth:
        hit = [index for index, finding in enumerate(findings) if matches(row, finding)]
        used.update(hit)
        expected_fail = row["expected"] == "FAIL"
        if expected_fail and hit:
            tp += 1
            outcome = "TP"
        elif expected_fail:
            fn += 1
            outcome = "FN"
        elif hit:
            fp += 1
            outcome = "FP"
        else:
            tn += 1
            outcome = "TN"
        detail.append((
            row["resource_type"], row["resource_id"],
            row["rule_id"], row["expected"], outcome,
        ))

    unlabelled = [finding for index, finding in enumerate(findings) if index not in used]
    return tp, fp, fn, tn, detail, unlabelled


def pct(numerator, denominator):
    return round(100 * numerator / denominator, 2) if denominator else 0.0


def main(ground_truth_path, findings_path):
    tp, fp, fn, tn, detail, unlabelled = evaluate(
        load(ground_truth_path), load(findings_path)
    )
    precision = pct(tp, tp + fp)
    recall = pct(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 2) if precision + recall else 0.0
    print(f"{'Resource type':22} {'Resource ID':36} {'Rule':8} {'Expected':8} Outcome")
    for resource_type, resource_id, rule_id, expected, outcome in detail:
        print(f"{resource_type:22} {resource_id:36} {rule_id:8} {expected:8} {outcome}")
    print(f"\nTP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"Accuracy  = {pct(tp + tn, tp + tn + fp + fn)}%")
    print(f"Precision = {precision}%")
    print(f"Recall    = {recall}%")
    print(f"F1-score  = {f1}%")
    print(f"FPR       = {pct(fp, fp + tn)}%")
    if unlabelled:
        print(f"\n{len(unlabelled)} finding(s) are not in the ground truth:")
        for finding in unlabelled:
            print(f"  {finding['rule_id']:8} {finding['resource_type']} {finding['resource_id']}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        main(sys.argv[1], sys.argv[2])
    except (OSError, ValueError, csv.Error) as error:
        sys.exit(f"Evaluation input error: {error}")
