# CTI Pipeline Project

A comprehensive Cyber Threat Intelligence (CTI) pipeline with AI integration for security vulnerability scanning, enrichment, and decision making.

## Project Structure

```
CTI-CICD/
├── .github/
│   └── workflows/
│       └── security-pipeline.yml      # CI/CD pipeline configuration
├── target_app/                         # Vulnerable test application
│   └── package.json
├── src/
│   ├── p1_scanner/                    # Phase 1: Security Scanner
│   │   ├── scanner.py                 # Main scanning logic
│   │   ├── config.yaml                # Scanner configuration
│   │   └── .trivyignore               # Trivy ignore patterns
│   ├── p2_enricher/                   # Phase 2: Threat Intelligence Enrichment
│   │   ├── enricher.py                # Enrichment logic
│   │   └── cache.sqlite               # Local cache for enrichment data
│   ├── p3_decision_engine/             # Phase 3: AI Decision Engine
│   │   ├── decision_engine.py         # AI-powered decision making
│   │   ├── config.yaml                # Decision engine configuration
│   │   └── prompts/                   # AI prompt templates
│   └── p4_dashboard/                  # Phase 4: Security Dashboard
├── shared/                             # Data transition files
│   ├── 1_raw_results.json             # Output from P1
│   ├── 2_enriched.json                # Output from P2
│   └── 3_final_report.json            # Output from P3
├── requirements.txt                    # Python dependencies
└── README.md                           # This file
```

## Setup

### 1. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Pipeline Phases

- **P1 (Scanner)**: Performs security vulnerability scanning on target applications
- **P2 (Enricher)**: Enriches vulnerability data with threat intelligence
- **P3 (Decision Engine)**: Uses AI to analyze and prioritize security findings
- **P4 (Dashboard)**: Visualizes results and provides security insights

## Usage

Run individual phases:

```bash
# Run scanner
python src/p1_scanner/scanner.py

# Run enricher
python src/p2_enricher/enricher.py

# Run decision engine
python src/p3_decision_engine/decision_engine.py
```

Or use the CI/CD pipeline for automated execution.

## Development

- Use the virtual environment for all Python development
- Follow the existing code structure and naming conventions
- Update requirements.txt when adding new dependencies
- Test each phase individually before integrating
