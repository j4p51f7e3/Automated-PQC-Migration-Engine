# Automated-PQC-Migration-Engine

A Static Application Security Testing (SAST) tool for detecting quantum-vulnerable and weak cryptographic usage and recommending Post-Quantum Cryptography (PQC) migrations.

## Features
- AST-based static analysis to detect crypto primitives (RSA, ECC, MD5, SHA-1).
- Deterministic PQC migration rules mapping.
- LLM Semantic Analysis to resolve ambiguous usage (e.g., distinguishing key establishment from digital signatures when only key generation is visible).

## Installation

```bash
pip install -r requirements.txt
```

## Running the Scanner

The scanner can run in two LLM modes: `mock` and `gemini`.

### Mock Mode (Offline Testing)
The default mode uses a deterministic mock LLM client. It is safe for offline testing and requires no API keys.

```bash
python main.py test_repository --llm mock
```
Alternatively, just running `python main.py test_repository` defaults to `mock` mode.

### Gemini Mode (Real LLM Integration)
To use the real Google Gemini LLM for semantic analysis, you must provide the API key as an environment variable. 
**Never commit your API key to source control.**

#### Windows PowerShell
```powershell
$env:GEMINI_API_KEY="your_api_key_here"
python main.py test_repository --llm gemini
```

#### Linux/macOS
```bash
export GEMINI_API_KEY="your_api_key_here"
python main.py test_repository --llm gemini
```

### Optional Environment Variables
- `GEMINI_MODEL`: Specifies the Gemini model to use (default: `gemini-2.5-flash`).
