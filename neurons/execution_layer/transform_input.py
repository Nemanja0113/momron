#!/usr/bin/env python3
import json
import sys
from typing import Any, Dict, List

# Expected signals per circuit.circom
SCALARS = [
    "RATE_OF_DECAY",
    "RATE_OF_RECOVERY",
    "FLATTENING_COEFFICIENT",
    "PROOF_SIZE_THRESHOLD",
    "PROOF_SIZE_WEIGHT",
    "RESPONSE_TIME_WEIGHT",
    "MAXIMUM_RESPONSE_TIME_DECIMAL",
    "COMPETITION_WEIGHT",
    "scaling",
]

ARRAYS = [
    "maximum_score",
    "previous_score",
    "verified",
    "proof_size",
    "response_time",
    "competition",
    "maximum_response_time",
    "minimum_response_time",
    "block_number",
    "validator_uid",
    "miner_uid",
]

def to_string_number(v: Any) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int,)):
        return str(v)
    if isinstance(v, float):
        # Circom expects integers; fail loudly if non-integer float
        if not v.is_integer():
            raise ValueError(f"non-integer float value: {v}")
        return str(int(v))
    if isinstance(v, str):
        return v
    raise ValueError(f"unsupported JSON type: {type(v)}")

def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: transform_input.py <input.json> <output.json> [batch_size]", file=sys.stderr)
        sys.exit(1)
    src = sys.argv[1]
    dst = sys.argv[2]
    batch_size = None
    if len(sys.argv) >= 4:
        try:
            batch_size = int(sys.argv[3])
        except Exception:
            raise ValueError("batch_size must be an integer")

    with open(src, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("top-level JSON must be an object of signalName: value")

    out: Dict[str, Any] = {}

    # Scalars: coerce to string numbers
    for key in SCALARS:
        if key in data:
            out[key] = to_string_number(data[key])

    # Arrays: ensure array and stringify elements
    for key in ARRAYS:
        if key in data:
            v = data[key]
            if not isinstance(v, list):
                v = [v]
            if batch_size is not None:
                v = v[:batch_size]
            out[key] = [to_string_number(x) for x in v]

    # Best-effort pass-through for any extra keys (stringify scalars, arrayify arrays)
    for key, v in data.items():
        if key in out:
            continue
        if isinstance(v, list):
            out[key] = [to_string_number(x) for x in v]
        else:
            out[key] = to_string_number(v)

    with open(dst, "w") as f:
        json.dump(out, f)

if __name__ == "__main__":
    main()


