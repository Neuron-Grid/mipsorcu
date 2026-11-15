"""Fail when cargo-vet exemptions are present without accepted audit evidence."""

import sys
import tomllib
from pathlib import Path


def check(path: Path) -> int:
    try:
        with path.open("rb") as config_file:
            config = tomllib.load(config_file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"ERROR: cannot read cargo-vet config: {error}", file=sys.stderr)
        return 1

    exemptions = config.get("exemptions", {})
    if not isinstance(exemptions, dict):
        print("ERROR: cargo-vet exemptions must be a TOML table", file=sys.stderr)
        return 1

    entries = []
    for crate, crate_exemptions in exemptions.items():
        if not isinstance(crate_exemptions, list):
            print(f"ERROR: exemptions.{crate} must be an array of tables", file=sys.stderr)
            return 1
        for exemption in crate_exemptions:
            if (
                not isinstance(exemption, dict)
                or not isinstance(exemption.get("version"), str)
                or not isinstance(exemption.get("criteria"), (str, list))
                or (isinstance(exemption.get("criteria"), list)
                    and not all(isinstance(value, str) for value in exemption["criteria"]))
            ):
                print(f"ERROR: malformed cargo-vet exemption for {crate}", file=sys.stderr)
                return 1
            criteria = exemption["criteria"]
            criteria_text = ",".join(criteria) if isinstance(criteria, list) else criteria
            entries.append(f"{crate}@{exemption['version']} (criteria={criteria_text})")

    if entries:
        print(f"ERROR: cargo-vet config contains {len(entries)} exemption(s) without accepted audit evidence:")
        for entry in entries:
            print(f"- {entry}")
        return 1

    print("OK: cargo-vet config contains no exemptions")
    return 0


if __name__ == "__main__":
    config_path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("supply-chain/config.toml")
    if len(sys.argv) > 2:
        print(f"Usage: {Path(sys.argv[0]).name} [config.toml]", file=sys.stderr)
        sys.exit(2)
    sys.exit(check(config_path))
