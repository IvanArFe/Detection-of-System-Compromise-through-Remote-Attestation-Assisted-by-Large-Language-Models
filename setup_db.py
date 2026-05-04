"""
Run once to create the required tables in Supabase:
    python setup_db.py

Requires in .env:
    SUPABASE_URL          — project URL (already used by the EDR)
    SUPABASE_ACCESS_TOKEN — personal access token from
                            https://supabase.com/dashboard/account/tokens
"""
import os
import re
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

TABLES = [
    (
        "detections",
        """
        CREATE TABLE IF NOT EXISTS detections (
            id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            created_at   TIMESTAMPTZ DEFAULT now(),
            pid          INTEGER NOT NULL,
            process      TEXT NOT NULL,
            decision     TEXT NOT NULL,
            action       TEXT,
            llm_round1   TEXT NOT NULL,
            llm_round2   TEXT,
            remediation  TEXT
        );
        """,
    ),
    (
        "evidence",
        """
        CREATE TABLE IF NOT EXISTS evidence (
            id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            created_at   TIMESTAMPTZ DEFAULT now(),
            detection_id UUID REFERENCES detections(id),
            tool         TEXT NOT NULL,
            result       TEXT NOT NULL
        );
        """,
    ),
]


def get_project_ref(supabase_url: str) -> str:
    match = re.search(r"https://([^.]+)\.supabase\.co", supabase_url)
    if not match:
        print("[!] Could not parse project ref from SUPABASE_URL")
        sys.exit(1)
    return match.group(1)


def run_sql(project_ref: str, token: str, sql: str):
    url = f"https://api.supabase.com/v1/projects/{project_ref}/database/query"
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}"},
        json={"query": sql},
    )
    if response.status_code not in (200, 201):
        print(f"[!] Error {response.status_code}: {response.text}")
        sys.exit(1)


def main():
    supabase_url = os.environ.get("SUPABASE_URL")
    access_token = os.environ.get("SUPABASE_ACCESS_TOKEN")

    if not supabase_url:
        print("[!] SUPABASE_URL not set in .env")
        sys.exit(1)
    if not access_token:
        print("[!] SUPABASE_ACCESS_TOKEN not set in .env")
        print("    Get one at: https://supabase.com/dashboard/account/tokens")
        sys.exit(1)

    project_ref = get_project_ref(supabase_url)
    print(f"[*] Setting up database for project: {project_ref}")

    for name, sql in TABLES:
        run_sql(project_ref, access_token, sql)
        print(f"[+] Table '{name}' ready.")

    print("\n[+] Database setup complete.")


if __name__ == "__main__":
    main()
