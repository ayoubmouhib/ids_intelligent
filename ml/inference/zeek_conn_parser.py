import argparse
import json
from pathlib import Path


# ============================================================
# ZEEK CONNECTION PARSER
# ============================================================
#
# Reads Zeek conn.log JSON records and converts them into
# normalized Python dictionaries.
#
# IMPORTANT:
# This script does NOT try to convert Zeek data into
# NSL-KDD features yet.
#
# Its job is only:
#
#     conn.log -> normalized connection records
#
# ============================================================


def parse_zeek_conn_log(input_file: Path) -> list[dict]:

    records = []

    with input_file.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            # Ignore empty lines
            if not line:
                continue

            # Ignore Zeek header/comment lines
            if line.startswith("#"):
                continue

            try:
                data = json.loads(line)

            except json.JSONDecodeError as error:

                print(
                    f"WARNING: Invalid JSON at line "
                    f"{line_number}: {error}"
                )

                continue

            # ------------------------------------------------
            # Normalize Zeek fields
            # ------------------------------------------------

            record = {
                "timestamp": data.get("ts"),

                "uid": data.get("uid"),

                "source_ip": data.get("id.orig_h"),
                "source_port": data.get("id.orig_p"),

                "destination_ip": data.get("id.resp_h"),
                "destination_port": data.get("id.resp_p"),

                "protocol": data.get("proto"),
                "service": data.get("service"),

                "duration": data.get("duration"),

                "source_bytes": data.get("orig_bytes"),
                "destination_bytes": data.get("resp_bytes"),

                "connection_state": data.get("conn_state"),

                "source_packets": data.get("orig_pkts"),
                "destination_packets": data.get("resp_pkts"),

                "source_ip_bytes": data.get("orig_ip_bytes"),
                "destination_ip_bytes": data.get("resp_ip_bytes"),

                "missed_bytes": data.get("missed_bytes"),

                "history": data.get("history"),

                "local_source": data.get("local_orig"),
                "local_destination": data.get("local_resp"),

                "ip_protocol": data.get("ip_proto"),
            }

            records.append(record)

    return records


def save_records(records: list[dict], output_file: Path):

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:

        for record in records:

            file.write(
                json.dumps(record)
                + "\n"
            )


def main():

    parser = argparse.ArgumentParser(
        description="Parse Zeek conn.log JSON output"
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Path to Zeek conn.log",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(
            "data/processed/zeek_connections.jsonl"
        ),
        help="Output JSONL file",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("ZEEK CONNECTION PARSER")
    print("=" * 70)

    print()
    print(f"Input : {args.input}")
    print(f"Output: {args.output}")

    print()
    print("Reading Zeek conn.log...")

    records = parse_zeek_conn_log(args.input)

    print(
        f"Parsed connections: {len(records)}"
    )

    if not records:

        print()
        print("WARNING: No valid Zeek records found.")
        return

    save_records(
        records,
        args.output,
    )

    print()
    print("Parser complete.")
    print(
        f"Saved: {args.output}"
    )

    print()
    print("First normalized record:")
    print(
        json.dumps(
            records[0],
            indent=2,
        )
    )

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
