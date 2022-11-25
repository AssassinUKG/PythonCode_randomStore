#!/usr/bin/env python3

import argparse
import itertools
import json
import xmltodict
import cairo
from math import pi
import os
import shutil
from datetime import datetime
import time

import unicodedata
import re


def datetime_from_utc_to_local(utc_datetime):
    now_timestamp = time.time()
    offset = datetime.fromtimestamp(
        now_timestamp) - datetime.utcfromtimestamp(now_timestamp)
    return utc_datetime + offset


def slugify(value, allow_unicode=False):
    """
    Taken from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize('NFKC', value)
    else:
        value = unicodedata.normalize('NFKD', value).encode(
            'ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^\w\s-]', '', value.lower())
    return re.sub(r'[-\s]+', '-', value).strip('-_')


def getPercent(num, total):
    return (num / total * 360)


def convertRGBColor(R, G, B):
    try:
        R_ = float(R) / 255
        G_ = float(G) / 255
        B_ = float(B) / 255
        return R_, G_, B_
    except:
        print("Could not parse RGB")
        return None


def getColorforvuln(name):
    if name == "critical":
        r, g, b = convertRGBColor("212", "63", "58")
        return r, g, b, 1
    if name == "high":
        r, g, b = convertRGBColor("238", "147", "54")
        return r, g, b, 1
    if name == "medium":
        r, g, b = convertRGBColor("253", "196", "49")
        return r, g, b, 1
    if name == "low":
        r, g, b = convertRGBColor("76", "174", "76")
        return r, g, b, 1
    if name == "info":
        r, g, b = convertRGBColor("53", "122", "189")
        return r, g, b, 1
    else:
        pass


def draw_segment(cr, a1, a2, rating):
    xc = 0.5
    yc = 0.5
    radius = 0.49
    angle1 = a1 * (pi / 180.0)  # angles are specified
    angle2 = a2 * (pi / 180.0)  # in radians

    r, g, b, a = getColorforvuln(rating)
    cr.set_source_rgba(r, g, b, a)
    # cr.set_source_rgb(r,g,b)
    cr.line_to(xc, yc)
    cr.arc(xc, yc, radius, angle1, angle2)
    cr.line_to(yc, xc)
    cr.fill()
    cr.stroke()


def path_ellipse(cr, x, y, width, height, angle=0):
    """
    x      - center x
    y      - center y
    width  - width of ellipse  (in x direction when angle=0)
    height - height of ellipse (in y direction when angle=0)
    angle  - angle in radians to rotate, clockwise
    """
    cr.save()
    cr.translate(x, y)
    cr.rotate(angle)
    cr.scale(width / 2.0, height / 2.0)
    cr.arc(0.0, 0.0, 1.0, 0.0, 2.0 * pi)
    cr.restore()


def draw_pieChart(stats):
    # stats will be str:int
    totalVuln = 0
    for s in stats:
        totalVuln += int(stats[s])
    # Get percent of all values

    CriticialPercent = getPercent(int(stats["critical"]), totalVuln)
    HighPercent = getPercent(int(stats["high"]), totalVuln)
    MediumPercent = getPercent(int(stats["medium"]), totalVuln)
    LowPercent = getPercent(int(stats["low"]), totalVuln)
    InfoPercent = getPercent(int(stats["info"]), totalVuln)

    t = CriticialPercent + HighPercent + MediumPercent + LowPercent + InfoPercent
    # print()
    # print(f"crit: {CriticialPercent}, high: {HighPercent}, med: {MediumPercent}, low: {LowPercent}, info: {InfoPercent}")
    # print(f"Total: {t}")
    # print()

    stats['critical'] = CriticialPercent
    stats['high'] = HighPercent
    stats['medium'] = MediumPercent
    stats['low'] = LowPercent
    stats['info'] = InfoPercent

    with cairo.SVGSurface("test.svg", 200, 200) as surface:
        context = cairo.Context(surface)

        context.scale(200, 200)
        cp_x, cp_y = 0.5, 0.5
        width = 0.99
        height = 0.99

        # Base Circle
        path_ellipse(context, cp_x, cp_y, width, height, pi / 2.0)
        context.set_line_width(0.01)
        context.set_source_rgba(0, 0, 0, 1)
        context.fill()

        lastPoint = 0
        for stat in stats:
            statPoint = stats[stat]
            start = lastPoint
            end = statPoint+start

            draw_segment(context, start, end, stat)
            lastPoint += statPoint
    with open("test.svg", "r") as content:
        svgContent = content.read()
    content.close()
    if os.path.exists("test.svg"):
        os.remove("test.svg")
    return svgContent


class Host(object):

    _info_count = 0
    _low_count = 0
    _medium_count = 0
    _high_count = 0
    _critical_count = 0
    _total_count = 0
    _host_ipaddress = None
    _report_filepath = None
    _start_report = None
    _end_report = None

    def __init__(self, hostname, vulns):
        self._hostname = hostname
        self._vulns = vulns

        # update totals
        for r in self._vulns:
            for v in r:
                if v == "risk_factor":
                    rating = r[v]
                    if rating == "Info":
                        self._info_count += 1
                    if rating == "Low":
                        self._low_count += 1
                    if rating == "Medium":
                        self._medium_count += 1
                    if rating == "High":
                        self._high_count += 1
                    if rating == "Critical":
                        self._critical_count += 1
                    self._total_count = self._critical_count + self._high_count + \
                        self._medium_count + self._low_count + self._info_count

    def print_vuln_stats(self):
        return print(f"Critical: {self._critical_count}, High: {self._high_count}, Medium: {self._medium_count}, Low: {self._low_count}, Info: {self._info_count}, Total: {self._total_count}")

    def getTotal(self):
        return self._total_count

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True)


class Report(object):
    def __init__(self):
        self.hosts = []

    def host_count(self):
        return len(self.hosts)

    def add_report(self, host, vulns, ip):
        host = Host(host, vulns)
        host._host_ipaddress = ip
        # host.print_vuln_stats()
        self.hosts.append(host)

    def all_reports(self):
        return self.hosts

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True)


def build_AccordionItem(vulnerability, synopsis, id):
    accodrionItemHTML = f"""
    <div class="accordion" id="accordion" role="tablist">
     <div class="accordion-item"> <div class="accordion-header" role="tab">
     <button class="accordion-button collapsed ui-state-hover" type="button" data-bs-toggle="collapse" data-bs-target="#accordion .item-{id}" aria-expanded="false" aria-controls="accordion .item-{id}">
     <span class="vulnlabel {vulnerability['risk_factor'].lower()}">{vulnerability['risk_factor'].upper()}</span>&nbsp;{vulnerability['plugin_name']}
     </button> </div> <div class="accordion-collapsed collapse item-{id}" role="tabpanel" data-bs-parent="#accordion">
     <div class="accordion-body"> <p>{synopsis}</p> </div> </div> </div> </div>"""
    return accodrionItemHTML


def sort_vlun_list(reportIn: Report):
    newVulnList = []
    # Order vulnlist by rating, infos first, criticals last
    allInfos = [
        x for x in reportIn._vulns if x['risk_factor'] == "Info"]
    allLowss = [
        x for x in reportIn._vulns if x['risk_factor'] == "Low"]
    allMediumss = [
        x for x in reportIn._vulns if x['risk_factor'] == "Medium"]
    allHighs = [
        x for x in reportIn._vulns if x['risk_factor'] == "High"]
    allCriticalss = [
        x for x in reportIn._vulns if x['risk_factor'] == "Critical"]
    newVulnList.extend(allCriticalss)
    newVulnList.extend(allHighs)
    newVulnList.extend(allMediumss)
    newVulnList.extend(allLowss)
    newVulnList.extend(allInfos)
    return newVulnList


def create_vulnbyHost(reportClass, template_file, report_directory, options):

    for report in reportClass.hosts:
        vulnList = sort_vlun_list(report)

        print(report._hostname)

        with open(template_file, 'r') as template:
            contents = template.read()

        htmlParts = []
        idCount = 0
        for v in vulnList:
            if not v:
                continue
            # synopsisCode = get_vuln_synopsis(v)
            # htmlPart = f"<button class=\"accordion {str(v['risk_factor']).lower()}\">{v['plugin_name']}</button>"
            # htmlPart += f"<div class=\"accordion-content\"><p>{synopsisCode}</p></div>"
            # htmlParts.append(htmlPart)
            # {str(v['risk_factor']).lower()}
            _host_ipaddress = report._host_ipaddress
            # riskFactor = str(v['risk_factor']).lower()
            synopsisCode = get_vuln_synopsis(v, _host_ipaddress)
            # htmlPart = f"<button class=\"accordion\"><span class=\"vulnlabel {riskFactor}\">{riskFactor.upper()}</span>{v['plugin_name']}</button>"
            # htmlPart += f"<div class=\"accordion-content\"><p>{synopsisCode}</p></div>"
            htmlPart = build_AccordionItem(v, synopsisCode, idCount)
            htmlParts.append(htmlPart)
            idCount += 1
            print(v['plugin_name'])
        contents = contents.replace(
            "|||TOTALFINDINGS|||", str(report._total_count))
        contents = contents.replace(
            "|||TOTALCRITICAL|||", str(report._critical_count))
        contents = contents.replace("|||TOTALHIGH|||", str(report._high_count))
        contents = contents.replace(
            "|||TOTALMEDIUM|||", str(report._medium_count))
        contents = contents.replace("|||TOTALLOW|||", str(report._low_count))
        contents = contents.replace(
            "|||TOTALINFORMATION|||", str(report._info_count))

        contents = contents.replace(
            "|||COMPANYNAME|||", options['customerName'])

        # Findings
        contents = contents.replace("|||REPLACEME||||", ''.join(htmlParts))
        # Hostname or IP
        contents = contents.replace(
            "|||HOSTNAME_IP|||", str(report._hostname).upper())

        # pie chart
        inputVars = {"critical": report._critical_count, "high": report._high_count,
                     "medium": report._medium_count, "low": report._low_count, "info": report._total_count}
        imageText = draw_pieChart(inputVars)

        contents = contents.replace("|||PIE-CHART|||", imageText)
        # add extra ../ to go back for assets files
        contents = contents.replace("assets/", "../assets/")
        # ------------------------------------------------------
        FILENAME = rf"{report._hostname.replace('.', '_').replace('-','_')}.html"
        SAVE_VULNSBYHOST_FOLDER = "host_reports"

        if not os.path.exists(report_directory):
            os.mkdir(report_directory)
        report_dir = os.path.join(report_directory, SAVE_VULNSBYHOST_FOLDER)
        if not os.path.exists(report_dir):
            os.mkdir(report_dir)

        report_dir = os.path.join(report_directory, SAVE_VULNSBYHOST_FOLDER)
        fullP = os.path.realpath(report_dir)
        SAVE_FILE = os.path.join(fullP, FILENAME)

        LOCALPATH = f".\{SAVE_VULNSBYHOST_FOLDER}\{FILENAME}"

        report._report_filepath = LOCALPATH

        with open(SAVE_FILE, 'w') as file:
            file.write(contents)


def cleanString(string):
    string = string.replace("<", "LT")
    string = string.replace(">", "GT")
    string = string.replace("`n", "<br />")
    return string


def get_vuln_synopsis(vuln, ip):
    # aa
    synopsis = vuln['synopsis']
    solution = vuln['solution']

    classtype = "HOLDER"
    _host_ipaddress = ip
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
    retHTML += f"{_host_ipaddress}</td></tr><tr><td>Port/Protocol</td><td>{port}/{protocol}/{servicename}</td></tr>"
    retHTML += "<tr><td>Description</td>"
    retHTML += f"<td class=\"tddesc\"><div class=\"divtoggle\">{cleanString(description)}</div><div class=\"link toggle\"/></td></tr>"
    retHTML += "<tr><td>Output</td>"
    retHTML += f"<td class=\"tdoutput\"><div class=\"divtoggle\">{cleanString(pluginoutput)}</div><div class=\"link toggle\" /></td></tr></table><br /><br />"

    return retHTML


def get_data_from_NessusFile(nessusFile):
    with open(nessusFile) as xml_file:
        data_dict = xmltodict.parse(xml_file.read())
    # Put json into a string, then load again to parse the structure
    json_string = json.dumps(data_dict)
    json_data = json.loads(json_string)
    NessusData = json_data['NessusClientData_v2']
    return NessusData


def parse_reports(reportData):
    reportClass = Report()
    # _host_ipaddress = [x for x in NessusData['Report']['ReportHost']['HostProperties']]
    for report in reportData:
        listofVulns = []

        _host_ipaddress = [x['#text'] for x in report['HostProperties']
                           ['tag'] if x['@name'] == "host-ip"][0]

        HOST_START = [x['#text'] for x in report['HostProperties']
                      ['tag'] if x['@name'] == "HOST_START"][0]

        HOST_END = [x['#text'] for x in report['HostProperties']
                     ['tag'] if x['@name'] == "HOST_END"][0]

        reportName = report['@name']
        reportItem = report['ReportItem']
        # print(f"HostName: {reportName}")
        # reportClass._host_ipaddress = _host_ipaddress
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
            # plugin_name = vuln['plugin_name']
            listofVulns.append(vuln)
        reportClass.add_report(reportName, listofVulns, _host_ipaddress)
    return reportClass


def get_reports(nessusFile):
    Report = get_data_from_NessusFile(nessusFile)['Report']
    Reports = Report['ReportHost']
    reportData = parse_reports(Reports)
# # Save json to a file for testing
#     with open("reportData.json", "w") as w:
#         jsonstr = json.dumps(reportData.toJSON())
#         jsonout = json.loads(jsonstr)
#         w.write(jsonout)
    return reportData


def replace_value_in_file(filename, replace_key, replace_value):
    with open(filename, "r") as r:
        content = r.read()
    content = str(content).replace(replace_key, str(replace_value))
    with open(filename, "w") as w:
        w.write(content)


def get_list_of_totalFindings_object(reports):
    total_C = []
    total_H = []
    total_M = []
    total_L = []
    total_I = []

# Need to look at this.
    for report in reports.hosts:
        if report._critical_count:
            total_C.append(report)
        if report._high_count:
            total_H.append(report)
        if report._high_count:
            total_M.append(report)
        if report._low_count:
            total_L.append(report)
        if report._info_count:
            total_I.append(report)

    reports_out = {
        "critical": total_C,
        "high": total_H,
        "medium": total_M,
        "low": total_L,
        "info": total_I,
    }
    return reports_out


def getall_findingTotals(reports):
    total_C = 0
    total_H = 0
    total_M = 0
    total_L = 0
    total_I = 0

    for report in reports.hosts:
        total_C += report._critical_count
        total_H += report._high_count
        total_M += report._medium_count
        total_L += report._low_count
        total_I += report._info_count

    counts = {
        "critical": total_C,
        "high": total_H,
        "medium": total_M,
        "low": total_L,
        "info": total_I,
    }
    return counts

# TODO : REWRITE WITH REPORTS NOT VULNS!!!


def uniq_hosts_from_report(reports):
    uniq_hosts = []
    for rep in reports.hosts:
        # print(rep)
        if rep._host_ipaddress not in uniq_hosts or rep._hostname not in uniq_hosts:
            #print(f"Added: {rep._hostname}, IP: {rep._host_ipaddress}")
            uniq_hosts.append(rep)
    return uniq_hosts


def loop_hostsTester(reports):

    uniq_hosts = []
    for rep in reports.hosts:
        # print(rep)
        if rep._host_ipaddress not in uniq_hosts or rep._hostname not in uniq_hosts:
            #print(f"Added: {rep._hostname}, IP: {rep._host_ipaddress}")
            uniq_hosts.append(rep)
    return uniq_hosts


def build_table_items(reports, column_length=3):
    # for i in range(0, len(list1), 6):
    #     print(list1[i:i+6])
    #vulnList = sort_vlun_list(report)
    allCounts = getall_findingTotals(reports)
    #listAll = get_list_of_totalFindings_object(reports)
    uniq_hosts = uniq_hosts_from_report(reports)
    # a
    #listAll = get_list_of_totalFindings_object(reports)
    total = 0
    allTds = []
    for rep in uniq_hosts:
        #vulnList = sort_vlun_list(rep)
        rep.print_vuln_stats()
        total += rep._total_count
        # print(vulnList)
        # if rep == "info":
        #     if reports[rep] == 0:
        #         #vulnsByhost[cat] = "0"
        #         TD_ROW = f"<td class=\"infobg\"><a href=\"{ item._report_filepath}\">{ item._hostname}</a></td>"
        #         allTds.append(TD_ROW)
        #         continue
        if rep._critical_count > 0:
            TD_ROW = f"<td class=\"criticalbg\"><a href=\"{rep._report_filepath}\">{rep._hostname}</a></td>"
            allTds.append(TD_ROW)
            continue
        if rep._high_count > 0 and rep._critical_count <= 0:
            TD_ROW = f"<td class=\"highbg\"><a href=\"{rep._report_filepath}\">{rep._hostname}</a></td>"
            allTds.append(TD_ROW)
            continue
        if rep._medium_count > 0 and rep._critical_count <= 0 and rep._high_count <= 0:
            TD_ROW = f"<td class=\"mediumbg\"><a href=\"{rep._report_filepath}\">{rep._hostname}</a></td>"
            allTds.append(TD_ROW)
            continue
        if rep._low_count > 0 and rep._critical_count <= 0 and rep._high_count <= 0 and rep._medium_count <= 0:
            TD_ROW = f"<td class=\"lowbg\"><a href=\"{rep._report_filepath}\">{rep._hostname}</a></td>"
            allTds.append(TD_ROW)
            continue
        else:
            TD_ROW = f"<td class=\"infobg\"><a href=\"{rep._report_filepath}\">{rep._hostname}</a></td>"
            allTds.append(TD_ROW)
        # for vuln in vulnList:
        # print(vuln._hostname)
        # risk_factor = r._vulns[i]['risk_factor']
        # # make class criticalbg, highbg, mediumbg, lowbg, infogb
        # if risk_factor is "Critical":
        #     allTds.append(
        #         f"<td class=\"criticalbg\"><a href=\"{r._report_filepath}\">{r._hostname}</a></td>")
        # if risk_factor is "High":
        #     allTds.append(
        #         f"<td class=\"highbg\"><a href=\"{r._report_filepath}\">{r._hostname}</a></td>")
        # if risk_factor is "Medium":
        #     allTds.append(
        #         f"<td class=\"mediumbg\"><a href=\"{r._report_filepath}\">{r._hostname}</a></td>")
        # if risk_factor is "Low":
        #     allTds.append(
        #         f"<td class=\"lowbg\"><a href=\"{r._report_filepath}\">{r._hostname}</a></td>")
        # if risk_factor is "Info":
        #     allTds.append(
        #         f"<td class=\"infobg\"><a href=\"{r._report_filepath}\">{r._hostname}</a></td>")

        # six per row
        # TD_ROW = f"<td class=\"lowbg\"><a href=\"{rep._report_filepath}\">{rep._hostname}</a></td>"
        # allTds.append(TD_ROW)
        # allTds.sort()
        print(f"total: {total}")
    # add a check for dupe items

    allTd_bysix = []
    for i in range(0, len(allTds), column_length):
        hns = ''.join(allTds[i:i+column_length])
        allTd_bysix.append(hns)
    final = []
    for td in allTd_bysix:
        final.append(f"<tr>{td}</tr>")
    returnString = ''.join(final)
    return returnString


def build_dashboard_page(reports, template_path, sorted_vulns_by_host, argparse_options):

    # Swap values in index.html page (customername, timereportGenerated, Findings, piechart, hosts...)
    c_time = os.path.getctime(argparse_options["input_file"])
    dt_c = datetime.fromtimestamp(c_time).strftime("%d/%m/%Y, %H:%M:%S")
    creationTime = dt_c
    # print(dt_c)
    replace_value_in_file(template_path, "|||TIMECREATED|||", creationTime)
    replace_value_in_file(template_path, "|||COMPANYNAME|||",
                          argparse_options['customerName'])
    allCounts = getall_findingTotals(reports)

    showInfos = False
    if not showInfos:
        sorted_vulns_by_host['info'] = 0
        replaceVar = '<li style="font-size: 14px;">Total Info:&nbsp;<span class="spanFindings" style="font-size: 14px;">|||TOTALINFORMATION|||</span></li>'
        replace_value_in_file(
            template_path, replaceVar, "")
    else:
        replace_value_in_file(
            template_path, "|||TOTALINFORMATION|||", allCounts['info'])

    TOTAL = (allCounts['critical'] + allCounts['high'] +
             allCounts['medium'] + allCounts['low'] + allCounts['info'])
    # TODO: inplement check here for info showing or not.
    hostnames_table = build_table_items(reports)

    replace_value_in_file(
        template_path, "|||TOTALCRITICAL|||", allCounts['critical'])
    replace_value_in_file(template_path, "|||TOTALHIGH|||",
                          allCounts['high'])
    replace_value_in_file(
        template_path, "|||TOTALMEDIUM|||", allCounts['medium'])
    replace_value_in_file(template_path, "|||TOTALLOW|||",
                          allCounts['low'])

    replace_value_in_file(template_path, "|||TOTALFINDINGS|||", TOTAL)

    # build table for index page
    #hostnames_table = build_table_items(reports)

    # print(hostnames_table)
    replace_value_in_file(template_path, "|||TABLEREPLACE|||", hostnames_table)

    imageText = draw_pieChart(allCounts)
    replace_value_in_file(template_path, "|||PIE-CHART|||", imageText)
    pass


def main():
    par = argparse.ArgumentParser()
    par.add_argument("-i", "--input-file",
                     help="a .nessus report file only", required=True)
    par.add_argument("-c", "--customerName",
                     help="Enter a customer name for the report", default="", required=False)
    args = par.parse_args()
    # Options (input_file | customerName)
    options = vars(args)

    # 1. Parse File
    # 2. Check prequisits (folder, assets, index files)
    # 3. Generate Dashboard
    # 4. Generate vulns by host
    # 5. Generate all vulns page
    # 6. profit !

    # set datetime string for filenames
    date = datetime.now().strftime("%d_%m_%Y-%I-%M-%S_%p")
    currDir = os.path.dirname(__file__)
    REPORT_DIR = f"report_{options['customerName']}_{date}"
    REPORT_DIR = slugify(REPORT_DIR)
    REPORT_DIR = rf"{currDir}\{REPORT_DIR}"
    ASSETS_DIR = rf"{REPORT_DIR}\assets"
    INDEX_PAGE = rf"{REPORT_DIR}\index.html"
    VULN_BY_HOST_TEMPLATE = rf"{currDir}\\files\template\vbh_template.html"

    # 1. Parse File
    reports = get_reports(options['input_file'])
    # 2. Check prequisits
    # Copy any assets over to the report folder
    assetsDirOriginal = os.path.join(currDir, "files\\assets")
    indexOriginal = os.path.join(currDir, "files\\index.html")
    # Copy main page (index - home page) over to the report folder
    # time.sleep(0.2)

    # Need better folder and file management functions.
    if not os.path.exists(INDEX_PAGE):
        os.mkdir(os.path.dirname(INDEX_PAGE))

    shutil.copyfile(indexOriginal, INDEX_PAGE)

    # Build Dashboard

    # Build VulnsByHost

    create_vulnbyHost(reports, VULN_BY_HOST_TEMPLATE, REPORT_DIR, options)

    # Build AllVulns

    # # Swap values in index.html page (customername, timereportGenerated, Findings, piechart, hosts...)
    # c_time = os.path.getctime(options["input_file"])
    # dt_c = datetime.fromtimestamp(c_time).strftime("%d/%m/%Y, %H:%M:%S")
    # creationTime = dt_c
    # # print(dt_c)
    # replace_value_in_file(INDEX_PAGE, "|||TIMECREATED|||", creationTime)
    # replace_value_in_file(INDEX_PAGE, "|||COMPANYNAME|||",
    #                       options['customerName'])
    # # Get and replace all total values
    # allCounts = getall_findingTotals(reports)

    # Remake how you loop the hosts and parseing data..... use the methond below for better results.
    allCounts = getall_findingTotals(reports)
    #dashboard_hosts = get_list_of_totalFindings_object(reports)
    build_dashboard_page(reports, INDEX_PAGE, allCounts, options)
    # print(dashboard_hosts)

    # # switch to omit info data static for now (testing)
    # showInfos = True
    # if not showInfos:
    #     allCounts['info'] = 0
    #     # regxStr = "<ul>(\n\s.*){5}"
    #     # with open(INDEX_PAGE, "r") as r:
    #     #     page = r.read()
    #     # x = re.search(regxStr, page)
    #     replaceVar = '<li style="font-size: 14px;">Total Info:&nbsp;<span class="spanFindings" style="font-size: 14px;">|||TOTALINFORMATION|||</span></li>'
    #     replace_value_in_file(
    #         INDEX_PAGE, replaceVar, "")
    # else:
    #     replace_value_in_file(
    #         INDEX_PAGE, "|||TOTALINFORMATION|||", allCounts['info'])

    # replace_value_in_file(
    #     INDEX_PAGE, "|||TOTALCRITICAL|||", allCounts['critical'])
    # replace_value_in_file(INDEX_PAGE, "|||TOTALHIGH|||", allCounts['high'])
    # replace_value_in_file(INDEX_PAGE, "|||TOTALMEDIUM|||", allCounts['medium'])
    # replace_value_in_file(INDEX_PAGE, "|||TOTALLOW|||", allCounts['low'])

    # TOTAL = (allCounts['critical'] + allCounts['high'] +
    #          allCounts['medium'] + allCounts['low'] + allCounts['info'])
    # replace_value_in_file(
    #     INDEX_PAGE, "|||TOTALFINDINGS|||", TOTAL)

    # imageText = draw_pieChart(allCounts)
    # replace_value_in_file(INDEX_PAGE, "|||PIE-CHART|||", imageText)

    # # build table for index page
    # hostnames_table = build_table_items(reports)
    # # print(hostnames_table)
    # replace_value_in_file(INDEX_PAGE, "|||TABLEREPLACE|||", hostnames_table)

    # Copy asset folder

    if os.path.exists(ASSETS_DIR):
        shutil.rmtree(ASSETS_DIR)
    shutil.copytree(
        assetsDirOriginal, ASSETS_DIR)


if __name__ == "__main__":
    main()


# Test: python.exe .\parse-nessus.py -i "C:\\Users\\ac1d\\Desktop\\Mysites\\vulnByHost\\jtc_xbzgqj.nessus" -c "Google"
