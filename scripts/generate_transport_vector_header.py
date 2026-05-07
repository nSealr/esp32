#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT.parent / "specs"
OUT = ROOT / "build/host_core/transport_vector.hpp"


def cpp_string(value: str) -> str:
    return json.dumps(value)


def main() -> int:
    vector = json.loads(
        (SPECS / "vectors/transports/serial-frame-request-kind-1-basic.json").read_text(encoding="utf-8")
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "\n".join(
            [
                "#pragma once",
                "",
                "namespace nostrseal::test_vectors {",
                f"constexpr const char* kSerialFrameType = {cpp_string(vector['type'])};",
                f"constexpr const char* kSerialFramePayloadBase64Url = {cpp_string(vector['payload_base64url'])};",
                f"constexpr const char* kSerialFrame = {cpp_string(vector['frame'])};",
                "}  // namespace nostrseal::test_vectors",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
