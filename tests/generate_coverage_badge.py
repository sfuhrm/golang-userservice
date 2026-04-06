import os
import sys

import requests

COVERAGE_URL = os.getenv("COVERAGE_URL", "http://localhost:8080/debug/coverage")
BADGE_SVG_PATH = os.getenv("BADGE_SVG_PATH", "coverage_badge.svg")
UNIT_COVERAGE_ENV = os.getenv("UNIT_COVERAGE")


def get_color(percentage):
    if percentage >= 80:
        return "brightgreen"
    if percentage >= 60:
        return "yellow"
    if percentage >= 40:
        return "orange"
    return "red"


def parse_unit_coverage():
    if not UNIT_COVERAGE_ENV:
        return None

    try:
        return float(UNIT_COVERAGE_ENV)
    except ValueError:
        print(f"ERROR: UNIT_COVERAGE is not a valid number: {UNIT_COVERAGE_ENV}")
        sys.exit(1)


def fetch_e2e_coverage():
    try:
        response = requests.get(COVERAGE_URL, timeout=5)
    except requests.exceptions.RequestException as exc:
        print(f"ERROR: Failed to fetch e2e coverage: {exc}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"ERROR: Coverage endpoint returned {response.status_code}")
        sys.exit(1)

    data = response.json()
    try:
        return float(data.get("coverage", 0))
    except (TypeError, ValueError):
        print(f"ERROR: Coverage endpoint payload is invalid: {data}")
        sys.exit(1)


def compute_combined_coverage(e2e_coverage, unit_coverage):
    if unit_coverage is None:
        return e2e_coverage
    return (e2e_coverage + unit_coverage) / 2.0


def generate_badge(percentage):
    color = get_color(percentage)

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20">
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="round">
    <rect width="140" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round)">
    <rect width="87" height="20" fill="#555"/>
    <rect x="87" width="53" height="20" fill="{color}"/>
    <path d="M0 0h5v20H0z" fill="{color}"/>
    <rect width="140" height="20" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="43.5" y="15" fill="#010101" fill-opacity=".3">coverage</text>
    <text x="43.5" y="14">coverage</text>
    <text x="113.5" y="15" fill="#010101" fill-opacity=".3">{percentage:.0f}%</text>
    <text x="113.5" y="14">{percentage:.0f}%</text>
  </g>
</svg>'''

    with open(BADGE_SVG_PATH, "w", encoding="utf-8") as file_handle:
        file_handle.write(svg)

    print(f"Badge saved to {BADGE_SVG_PATH}")


def main():
    e2e_coverage = fetch_e2e_coverage()
    unit_coverage = parse_unit_coverage()
    combined_coverage = compute_combined_coverage(e2e_coverage, unit_coverage)

    generate_badge(combined_coverage)

    print(f"E2E coverage: {e2e_coverage:.1f}%")
    if unit_coverage is not None:
        print(f"Unit coverage: {unit_coverage:.1f}%")
        print("Combined coverage formula: (e2e + unit) / 2")
    else:
        print("Unit coverage: not provided")
    print(f"Coverage shown in badge: {combined_coverage:.1f}%")


if __name__ == "__main__":
    main()
