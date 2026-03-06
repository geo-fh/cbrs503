import json
from mdutils import MdUtils
from mdutils.tools import TextUtils


def save_json_report(findings, output_path):
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=4)
    except Exception as e:
        print(f"Error saving JSON: {e}")


def open_report(json_report):
    with open(json_report, "r", encoding="utf-8") as file:
        data_list = json.load(file)
    return data_list


def save_md_report(report, output_path):
    md_report = MdUtils(file_name=output_path, title="Vulnerability Report")
    curr_file = ""
    md_report.new_header(level=1, title=f"{len(report)} Code Findings")
    for finding in report:
        if curr_file != finding["file"]:
            curr_file = finding["file"]
            md_report.new_header(
                level=2, title=TextUtils.text_format(text=curr_file, color="blue")
            )
        else:
            md_report.new_line(text="---")
        md_report.new_line(text=f"\t{finding["line"]}")
        md_report.new_line(text=f"\n**{finding["owasp_category"]}**")
        md_report.new_line(
            text=f"\n**Confidence: {str(finding["confidence_score"])}**")
        md_report.new_line(
            text=f"\n**Risk Summary:** \n{finding["risk_summary"]}")
        md_report.new_line(
            text=f"\n**Recommendation:** \n{finding["fix_recommendation"]}\n"
        )
    md_report.create_md_file()
    return
