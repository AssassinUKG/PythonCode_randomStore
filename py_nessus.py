#!/usr/bin/env python3
import json
import xmltodict

NESSUSFILE = r"C:\Users\ac1d\Desktop\NessusPython\jtc_xbzgqj.nessus"


# Convert Xml to JSON
with open(NESSUSFILE) as xml_file:
    data_dict = xmltodict.parse(xml_file.read())
# Put json into a string, then load again to parse the structure
json_string = json.dumps(data_dict)
json_data = json.loads(json_string)

# NessusClientData_v2
# - Report
#   - ReportHost
#   - ReportItem
# - Policy


NessusData = json_data['NessusClientData_v2']
Reports = NessusData['Report']['ReportHost']

for report in Reports:
    reportName = report['@name']
    reportItem = report['ReportItem']
    print(f"HostName: {reportName}")
    for vuln in reportItem:

        # Cvss3 Score
        cvss3_score = float(vuln['cvss3_base_score']) if (
            'cvss3_base_score' in vuln) else 0  # check if the key exists else set 0

        # Risk Factor
        riskFactor = vuln['risk_factor']
        # Change and update the value for None to Low
        riskFactor = "I" if riskFactor == 'None' else riskFactor
        vuln['risk_factor'] = riskFactor

        # If Risk = High and Cvss3 score > 8.9 Rate CRITICAL
        if cvss3_score > 8.9:
            vuln['risk_factor'] = "Critical"
            riskFactor = vuln['risk_factor']

        plugin_name = vuln['plugin_name']
        print(f"{plugin_name}, Rating: {riskFactor},  cvss3: {cvss3_score}")


# print(reports)
