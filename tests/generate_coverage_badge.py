import requests
import sys
import os

COVERAGE_URL = os.getenv("COVERAGE_URL", "http://localhost:8080/debug/coverage")
BADGE_SVG_PATH = os.getenv("BADGE_SVG_PATH", "coverage_badge.svg")

def get_color(percentage):
    if percentage >= 80:
        return "brightgreen"
    elif percentage >= 60:
        return "yellow"
    elif percentage >= 40:
        return "orange"
    else:
        return "red"

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
    
    with open(BADGE_SVG_PATH, 'w') as f:
        f.write(svg)
    
    print(f"Badge saved to {BADGE_SVG_PATH}")
    print(f"Coverage: {percentage:.1f}%")
    return percentage

def main():
    try:
        r = requests.get(COVERAGE_URL, timeout=5)
        if r.status_code != 200:
            print(f"ERROR: Coverage endpoint returned {r.status_code}")
            sys.exit(1)
        
        data = r.json()
        percentage = data.get("coverage", 0)
        
        generate_badge(percentage)
        
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to fetch coverage: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
