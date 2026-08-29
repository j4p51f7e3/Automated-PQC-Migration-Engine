import os
import sys
import json
import argparse
import io
from contextlib import redirect_stdout

from scanner.parser import parse_file
from scanner.detector import detect_crypto
from scanner.migration.analyzer import MigrationAnalyzer
from scanner.llm.client import MockLLMClient
from scanner.llm.gemini_client import GeminiLLMClient
from scanner.llm.analyzer import LLMAnalyzer


def format_text_finding(finding, finding_counter, include_migration, llm_result=None):
    """
    Format a single finding as text.
    Relies on finding.display() as the source of truth for base formatting,
    injecting migration info if requested.
    """
    lines = []
    if include_migration:
        lines.append(f"Finding #{finding_counter}")
        
    f = io.StringIO()
    with redirect_stdout(f):
        finding.display()
    
    display_output = f.getvalue().strip().split("\n")
    
    if include_migration:
        migration_result = MigrationAnalyzer.analyze(finding, llm_result)
        if migration_result:
            # Insert migration info before the final separator line
            insert_idx = len(display_output)
            for i in range(len(display_output)-1, -1, -1):
                if display_output[i].startswith("---"):
                    insert_idx = i
                    break
            
            alts = ", ".join(migration_result.alternative_replacements) if migration_result.alternative_replacements else "None"
            mig_lines = [
                "",
                "Migration:",
                f"Type           : {migration_result.migration_type}",
                f"Primary        : {migration_result.primary_replacement}",
                f"Alternatives   : {alts}",
                f"Manual Review  : {'YES' if migration_result.manual_review_required else 'NO'}",
                "",
                "Reason:",
                migration_result.reason or ""
            ]
            
            display_output = display_output[:insert_idx] + mig_lines + display_output[insert_idx:]
            
    if llm_result:
        llm_lines = [
            "",
            "Semantic Analysis:",
            f"Purpose        : {llm_result.purpose.value}",
            f"Confidence     : {llm_result.confidence.value}",
            "",
            "Evidence:"
        ]
        if llm_result.evidence:
            for ev in llm_result.evidence:
                llm_lines.append(f"- {ev}")
        else:
            llm_lines.append("None")
            
        llm_lines.extend([
            "",
            "Reasoning:",
            llm_result.reasoning or "None",
            "",
            f"Manual Review  : {'YES' if llm_result.manual_review_required else 'NO'}"
        ])
        
        insert_idx = len(display_output)
        for i in range(len(display_output)-1, -1, -1):
            if display_output[i].startswith("---"):
                insert_idx = i
                break
        display_output = display_output[:insert_idx] + llm_lines + display_output[insert_idx:]
            
    lines.extend(display_output)
    return "\n".join(lines)


def run_orchestration(directory, is_json, include_migration, llm_mode, output_file=None):
    if not os.path.exists(directory):
        print(f"Error: Target '{directory}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    if not os.path.isdir(directory):
        print(f"Error: Target '{directory}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    total_files = 0
    all_findings = []
    
    text_output_lines = []
    
    def emit(text):
        if not is_json and not output_file:
            print(text)
        text_output_lines.append(text)

    emit("")
    emit("=" * 60)
    emit("        PQC MIGRATION ENGINE")
    emit("=" * 60)
    emit("")
    emit(f"Scanning directory: {directory}")
    emit("")
    
    finding_counter = 1
    llm_results_map = {}
    
    # Setup LLM Client based on mode
    if llm_mode == "gemini":
        llm_client = GeminiLLMClient()
    else:
        llm_client = MockLLMClient()
        
    llm_analyzer = LLMAnalyzer(llm_client)

    for root, directories, files in os.walk(directory):
        for filename in files:
            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(root, filename)
            total_files += 1

            emit(f"[SCANNING] {file_path}")

            try:
                tree = parse_file(file_path)
            except (SyntaxError, UnicodeDecodeError, OSError) as e:
                print(f"Warning: Could not parse {file_path}: {e}", file=sys.stderr)
                continue
            except Exception as e:
                print(f"Warning: Unexpected failure parsing {file_path}: {e}", file=sys.stderr)
                continue

            if tree is None:
                continue

            try:
                findings = detect_crypto(file_path, tree)
            except Exception as e:
                print(f"Warning: Unexpected failure during detection in {file_path}: {e}", file=sys.stderr)
                continue
                
            all_findings.extend(findings)

            for finding in findings:
                llm_result = llm_analyzer.analyze_finding(finding)
                llm_results_map[id(finding)] = llm_result
                
                finding_text = format_text_finding(finding, finding_counter, include_migration, llm_result)
                emit(finding_text)
                finding_counter += 1

    emit("")
    emit("=" * 60)
    emit("SCAN COMPLETE")
    emit("=" * 60)
    emit(f"Files scanned : {total_files}")
    emit(f"Findings      : {len(all_findings)}")
    emit("")
    
    if is_json:
        report_dict = {
            "target": directory,
            "files_scanned": total_files,
            "findings": []
        }
        for finding in all_findings:
            finding_dict = finding.to_dict()
            llm_result = llm_results_map.get(id(finding))
            
            if include_migration:
                migration_result = MigrationAnalyzer.analyze(finding, llm_result)
                if migration_result:
                    finding_dict["migration"] = migration_result.to_dict()
                else:
                    finding_dict["migration"] = None
                    
            llm_result = llm_results_map.get(id(finding))
            if llm_result:
                finding_dict["llm_analysis"] = {
                    "purpose": llm_result.purpose.value,
                    "confidence": llm_result.confidence.value,
                    "evidence": llm_result.evidence,
                    "reasoning": llm_result.reasoning,
                    "manual_review_required": llm_result.manual_review_required
                }
                
            report_dict["findings"].append(finding_dict)
            
        final_output = json.dumps(report_dict, indent=4)
    else:
        final_output = "\n".join(text_output_lines)
        
    if output_file:
        with open(output_file, 'w') as f:
            f.write(final_output)
    elif is_json:
        print(final_output)


def main():
    parser = argparse.ArgumentParser(description="PQC Migration Engine")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("--migration", action="store_true", help="Include migration analysis")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--llm", choices=["mock", "gemini"], default="mock", help="Select LLM provider for semantic analysis")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    run_orchestration(
        directory=args.target, 
        is_json=(args.format == "json"), 
        include_migration=args.migration, 
        llm_mode=args.llm,
        output_file=args.output
    )


if __name__ == "__main__":
    main()