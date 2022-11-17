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


class Report(object):

    class Host(object):

        infoCount = 0
        lowCount = 0
        mediumCount = 0
        highCount = 0
        criticalCount = 0
        totalCount = 0

        def __init__(self, hostname, vulns):
            self.hostname = hostname
            self.vulns = vulns

            # update totals
            for r in self.vulns:
                for v in r:
                    if v == "risk_factor":
                        rating = r[v]
                        if rating == "Info":
                            self.infoCount += 1
                        if rating == "Low":
                            self.lowCount += 1
                        if rating == "Medium":
                            self.mediumCount += 1
                        if rating == "High":
                            self.highCount += 1
                        if rating == "Critical":
                            self.criticalCount += 1
                        self.totalCount = self.criticalCount + self.highCount + \
                            self.mediumCount + self.lowCount + self.infoCount

        def print_vuln_stats(self):
            return print(f"Critical: {self.criticalCount}\nHigh: {self.highCount}\nMedium: {self.mediumCount}\nLow: {self.lowCount}\nInfo: {self.infoCount}\nTotal: {self.totalCount}")

    # End Host

    def __init__(self):
        self.hosts = []

    def host_count(self):
        return len(self.hosts)

    def add_report(self, host, vulns):
        host = self.Host(host, vulns)
        host.print_vuln_stats()
        self.hosts.append(host)

    def all_reports(self):
        return self.hosts


NessusData = json_data['NessusClientData_v2']
Reports = NessusData['Report']['ReportHost']

# Loop data and fix some data (add vuln info level)
# Info, Low, Medium, High, Critical

reportClass = Report()
for report in Reports:
    listofVulns = []
    infoCount = 0
    lowCount = 0
    mediumCount = 0
    highCount = 0
    criticalCount = 0

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
        riskFactor = "Info" if riskFactor == 'None' else riskFactor
        vuln['risk_factor'] = riskFactor

        # If Risk = High and Cvss3 score > 8.9 Rate CRITICAL
        if cvss3_score > 8.9:
            vuln['risk_factor'] = "Critical"
            riskFactor = vuln['risk_factor']

        # Set risk totals (info, low, medium, high, critical)

        plugin_name = vuln['plugin_name']
        #print(f"{plugin_name}, Rating: {riskFactor},  cvss3: {cvss3_score}")
        listofVulns.append(vuln)
    reportClass.add_report(reportName, listofVulns)
    # print(reportClass)
    print("\n")

# print(reports)

# allTotals = 0
# for rep in reportClass.hosts:
#     allTotals += rep.totalCount
# print(f"Total Vulns: {allTotals}")


# Loop here and make template report


def create_vulnbyHost(reportClass, template_file):

    for rep in reportClass.hosts:

        # Name rep.hostname
        # Vulns rep.vulns (loop this build html)
        # Basic accordion structure

        #      <button class="accordion">Website Design and Development</button>
        #   <div class="accordion-content">
        #     <p>
        #       Whether you need a wordpress website, a shopify site, or a custom fullstack application, we got you! No matter
        #       what kind of website or application you need, it will be made with clean and maintable code that follows modern
        #       development standards. We also have top notch designers that can make unique designs that will make your website
        #       look different and unique. Not to mention that we also provide 24/7 website maintenance so that you get all the
        #       support you need.
        #     </p>
        #   </div>

        newVulnList = []
        # Order vulnlist by rating, infos first, criticals last
        allInfos = [
            x for x in vulnList if x['risk_factor'] == "Info"]
        allLowss = [
            x for x in vulnList if x['risk_factor'] == "Low"]
        allMediumss = [
            x for x in vulnList if x['risk_factor'] == "Medium"]
        allHighs = [
            x for x in vulnList if x['risk_factor'] == "High"]
        allCriticalss = [
            x for x in vulnList if x['risk_factor'] == "Critical"]
        newVulnList.extend(allCriticalss)
        newVulnList.extend(allHighs)
        newVulnList.extend(allMediumss)
        newVulnList.extend(allLowss)
        newVulnList.extend(allInfos)

        hostname = rep.hostname
        vulnList = rep.vulns

        print(hostname)

        TEMPLATE_FILE = template_file

        with open(TEMPLATE_FILE, 'r') as template:
            contents = template.read()

        htmlParts = []
        for v in vulnList:
            if not v:
                continue
            synopsisCode = get_vuln_synopsis(v)
            htmlPart = f"<button class=\"accordion {str(v['risk_factor']).lower()}\">{v['plugin_name']}</button>"
            htmlPart += f"<div class=\"accordion-content\"><p>{synopsisCode}</p></div>"
            htmlParts.append(htmlPart)
            print(v['plugin_name'])
        contents = contents.replace("<<||REPLACE||ME>>", ''.join(htmlParts))

        SAVE_FILE = rf"C:\Users\ac1d\Desktop\NessusPython\TestingTemplates\ByHost\{hostname.replace('.', '_')}.html"

        with open(SAVE_FILE, 'w') as file:
            file.write(contents)
        # print(contents)


def cleanString(string):
    string = string.replace("<", "LT")
    string = string.replace(">", "GT")
    string = string.replace("`n", "<br />")
    return string


def get_vuln_synopsis(vuln):
    # aa
    synopsis = vuln['synopsis']
    solution = vuln['solution']

    classtype = "HOLDER"
    ipaddress = "HOLDER"
    port = vuln['@port']
    protocol = vuln['@protocol']
    servicename = vuln['@svc_name']
    description = vuln['description']
    pluginoutput = vuln['plugin_output'] if "plugin_output" in vuln else ""
    # systeminfo
    retHTML = "<div><strong>Summary Information</strong><br /><br />"
    retHTML += "<table><tr><td>Synopsis</td><td>"
    retHTML += f"{cleanString(synopsis)}</td></tr><tr><td>Solution</td><td>"
    retHTML += f"{cleanString(solution)}</td></tr></table><br /><br /><strong>Details By Port</strong><br /><br /></div>"

    retHTML += "<table>"
    retHTML += f"<tr class=\"{classtype}\"><td>IP Address</td><td>"
    retHTML += f"{ipaddress}</td></tr><tr><td>Port/Protocol</td><td>{port}/{protocol}/{servicename}</td></tr>"
    retHTML += "<tr><td>Description</td>"
    retHTML += f"<td class=\"tddesc\"><div class=\"divtoggle\">{cleanString(description)}</div><div class=\"link toggle\"/></td></tr>"
    retHTML += "<tr><td>Output</td>"
    retHTML += f"<td class=\"tdoutput\"><div class=\"divtoggle\">{cleanString(pluginoutput)}</div><div class=\"link toggle\" /></td></tr></table><br /><br />"

    return retHTML


create_vulnbyHost(
    reportClass, r"C:\Users\ac1d\Desktop\NessusPython\TestingTemplates\index.html")
