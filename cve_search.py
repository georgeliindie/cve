#===============================================================================
#
# The content of this file or document is CONFIDENTIAL and PROPRIETARY
# to indie Semiconductor. It is subject to the terms of a License Agreement
# between Licensee and indie Semiconductor, restricting among other things,
# the use, reproduction, distribution and transfer. Each of the embodiments,
# including this information and any derivative work shall retain this
# copyright notice.
#
# Copyright 2024 Ay Dee Kay, LLC dba indie Semiconductor.
# All rights reserved.
#
#===============================================================================

#==========================
# Version history:
# v0.1 - Initial creation
# v0.2 - 1) Add search for keywords with token/delimiter around the word to accommodate 
#           the missing case showed in the "xtensa" search.
#        2) Add two columns: "new/updated", "version" to the report
#        3) Add projects in .ini and support multi-projects
#==========================

# !/usr/bin/env python
from __future__ import print_function

from configparser import ConfigParser
import getopt
import sys
import pprint
import git
import os
import json
import re
from os.path import expanduser
from pathlib import Path
from datetime import datetime, timedelta
import shutil

__version__ = '0.2.'
banner = f'Indie CVE Vulnerabilities Searcher. V{__version__}'

# Assume cloned CVS repo stored under this folder
home_folder = expanduser("~")
cvelistV5_dir = f'{home_folder}/cvelistV5'

# for log and test report
CVE_LOG_FILENAME_PRE = 'indie_cve_log'
CVE_REPORT_FILENAME_PRE = 'indie_cve_report'
log_file_handler = None

# this keyword which is used in interesting list will be used in generic search.
# Any keyword which is being used for searching can be stored in it.
GENERIC_SEARCH = 'Generic_Search'
# keyword delimiters
GENERIC_SEARCH_DELIMITERS = ['_', '-', ' ', '.', ',', ':', '/', '\\']


# to store retrieved CVE report based on vendor_products_keywords
total_cve_lists = {}

def cve_log(msg, need_timestamp=True):
    """Add timestamp to message and write them to log file and the screen

    :param str msg: to be written to screen/file
    :param bool need_timestamp:
        True: Add timestamp
        False: No timestamp
    :return:
    """
    if need_timestamp:
        date_string = f'{datetime.now():%Y-%m-%d %H:%M:%S%z}'
        log_file_handler.write(f'[{date_string}] {msg} \n')
    else:
        log_file_handler.write(f'{msg} \n', )
    print(msg)

def find_whole_word(w):
    """search whole from the string

    :param str w: to be searched
    :return:
        True: found
        False: not found
    rtybe: bool
    """
    return re.compile(r'\b({0})\b'.format(w), flags=re.IGNORECASE).search

def do_update_latest_cve_database(git_url):
    """Clone Github CVE project if not existing in local, otherwise, pull it
       to update local database

    :param str git_dir: Guthub URL
    :return:
    """

    # go to local CVE database repo to update by 'git pull' if cloned. Otherwise, clone it.
    current_folder = os.getcwd()
    if not os.path.exists(cvelistV5_dir):
        cve_log(f'There is no CVE database existing in {home_folder}. Need to take a while to clone...')
        git.Git(home_folder).clone(git_url)
    else:
        os.chdir(cvelistV5_dir)
        os.getcwd()
        # use git pull to see if we have updated CVE database
        g = git.cmd.Git(git_url)
        commits = g.pull()
        if commits:
            cve_log('Github CVE data is updated.')
            committed_cve_lists = pprint.pformat(commits)
            cve_log(f'New commits: {committed_cve_lists}')
        else:
            cve_log('no update on Github CVE database.')

    os.chdir(current_folder)
    os.getcwd()


def parse_cve_json(json_file):
    """Parse a CVE json file base on Indie vendors/products keywords. If found, add it to the list

    :param str json_file:
    :return:
        True: this CVE ID will be added
        False: this CVE ID will be ignored
    :rtype: bool
    """

    global total_cve_lists

    cve_id_from_json_file_name = os.path.basename(json_file)

    with open(json_file, 'r', encoding='utf-8') as j_file:

        # Read the contents of the file
        cve_json_contents  = json.load(j_file)
        dataVersion = cve_json_contents['dataVersion']
        cna = cve_json_contents ['containers']['cna']
        # ignore this case if rejectedReasons existing
        if 'rejectedReasons' in cna.keys():
            cve_log(f'Waring: ignore this file as it is rejected in {cve_id_from_json_file_name}')
            return False
        desc = cna['descriptions'][0]['value'].lower()
        problem_types_descriptions = None
        if 'problemTypes' in cna.keys():
            problem_types_descriptions = str(cna['problemTypes']).lower()
        cve_id = os.path.splitext(os.path.basename(json_file))[0]

        # CVE-2022-47637.json has no dateUpdated in cna['providerMetadata'].keys()
        dateUpdated = None
        if 'dateUpdated' in cna['providerMetadata'].keys():
            dateUpdated = cna['providerMetadata']['dateUpdated']
        else:
            # see if we can find it from another location
            if 'dateUpdated' in cve_json_contents ['cveMetadata'].keys():
                dateUpdated = cve_json_contents ['cveMetadata']['dateUpdated']

        # if we don't have update date info, consider it valid
        if dateUpdated:
            # some date including 'Z' at the end and need to remove to handle
            dateUpdated = re.sub('[Z]', '', dateUpdated)

            if '.' in dateUpdated:
                # use .%f as date may contain microseconds
                this_time = datetime.strptime(dateUpdated, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                this_time = datetime.strptime(dateUpdated, "%Y-%m-%dT%H:%M:%S")

            # ignore older record
            if this_time < past:
                cve_log(f'Ignore this {cve_id} which was updated at {dateUpdated} as it is older than requested {past_days} days')
                return False

        # first to search for generic search
        # Put any interesting keyword in GENERIC_SEARCH, which means here to search interesting words in
        # whole CVE JSON file, not limited in vendor, products, or description.
        if GENERIC_SEARCH.lower() in formatted_vendor_products.keys():
            for keyword in vendor_products_keywords_lower_case[GENERIC_SEARCH.lower()]:
                json_str = str(cve_json_contents).lower()
                xs = [m.start() for m in re.finditer(keyword, json_str)]
                if xs:
                    for x in xs:
                        if x >= 0:
                            # get the neighbours of the keyword in json_str
                            found_left_neighbour_in_delimiter_table = True
                            found_right_neighbour_in_delimiter_table = True
                            if x > 0:
                                l_n = json_str[x-1]
                                if l_n not in GENERIC_SEARCH_DELIMITERS:
                                    found_left_neighbour_in_delimiter_table = False
                            r_n = json_str[x + len(keyword)]
                            if r_n not in GENERIC_SEARCH_DELIMITERS:
                                found_right_neighbour_in_delimiter_table = False
                            if found_left_neighbour_in_delimiter_table and found_right_neighbour_in_delimiter_table:
                                list_reason = f'keyword {keyword} found in cna'
                                cve_log(f'{list_reason} in {cve_id_from_json_file_name}. Set it.')
                                total_cve_lists[cve_id] = [dateUpdated, desc, list_reason, dataVersion, dateUpdated]
                                return True

        for vdor, prods in formatted_vendor_products.items():
            for prod in prods:
                if find_whole_word(vdor)(desc) and find_whole_word(prod)(desc):
                    list_reason = f'Both vendor {vdor} and product {prod} found in desc'
                    cve_log(f'{list_reason} in {cve_id_from_json_file_name}. Set it.')
                    total_cve_lists[cve_id] = [dateUpdated, desc, list_reason, dataVersion, dateUpdated]
                    return True

        for r in cna['affected']:
            # CVE-2023-0118.json has no vendor in its first record
            if 'vendor' in r.keys():
                vendor = r['vendor'].lower()
                # CVE-2019-5017.json contains vendor/product info in 'versions'
                version = None
                if 'versions' in r:
                    version = r['versions'][0]['version'].lower()
                    for vdor, prods in formatted_vendor_products.items():
                        for prod in prods:
                            if find_whole_word(vdor)(version) and find_whole_word(prod)(version):
                                list_reason = f'Both vendor {vdor} and product {prod} found in version'
                                cve_log(f'{list_reason} in {cve_id_from_json_file_name}. Set it.')
                                total_cve_lists[cve_id] = [dateUpdated, desc, list_reason, dataVersion, dateUpdated]
                                return True
                # CVE-2023-51391.json has 'vendor' but no 'product'
                if 'product' in r.keys():
                    product = r['product'].lower()
                else:
                    product = 'nnn/aaa'
                for vdor, prods in formatted_vendor_products.items():
                    for prod in prods:
                        if vdor == vendor:
                            if prod == product:
                                list_reason = f'Both vendor {vdor} and product {prod} found in vendor/product'
                                cve_log(f'{list_reason} in {cve_id_from_json_file_name}. Set it.')
                                total_cve_lists[cve_id] = [dateUpdated, desc, list_reason, dataVersion, dateUpdated]
                                return True
                            else:
                                # product info in desc for CVE-2017-7749.json
                                if find_whole_word(prod)(desc):
                                    list_reason = f'Found vendor {vdor} in affected and product {prod} in desc'
                                    cve_log(f'{list_reason} in {cve_id_from_json_file_name}. Set it.')
                                    total_cve_lists[cve_id] = [dateUpdated, desc, list_reason, dataVersion, dateUpdated]
                                    return True
                                # product info in problemTypes/descriptions in CVE-2019-9820.json
                                if problem_types_descriptions and find_whole_word(prod)(problem_types_descriptions):
                                    list_reason = f'Found vendor {vdor} in affected and product {prod} in problemTypes desc'
                                    cve_log(f'{list_reason} in {cve_id_from_json_file_name}. Set it.')
                                    total_cve_lists[cve_id] = [dateUpdated, desc, list_reason, dataVersion, dateUpdated]
                                    return True

    cve_log(f'Warning: ignore this file as all keywords not found in {cve_id_from_json_file_name}.')
    return False


def browse_json_files_and_parse():
    """browse CVE json files and parse

    :return: URL string contains CVE search site to CVE ID and repo CVE source
    :rtype: str
    """

    file_urls = ''

    path = cvelistV5_dir + '\\cves'
    ignored_jsons = ['delta.json', 'deltaLog.json']
    # Recursively iterate through the directory and its subdirectories
    for root, dirs, files in os.walk(path):
        for name in files:
            if name not in ignored_jsons:
                if name.endswith((".json")):
                    if parse_cve_json(f'{root}\\{name}'):
                        file_name_base = Path(name).stem
                        file_urls += '<tr>'
                        file_urls += f'<th><a href="{cve_search_site_url}?name={file_name_base}">{file_name_base}</a></h>'
                        # point to source json file on Github
                        updated_root_for_github = f'{cve_root_repo_url}' + root.split('cves')[1]
                        file_urls += f'<th><a href="{updated_root_for_github}/{name}">{name}</a></th>'
                        file_urls += f'<th>{total_cve_lists[file_name_base][2]}</th>'
                        file_urls += f'<th>{total_cve_lists[file_name_base][4]}</th>'
                        file_urls += f'<th>{total_cve_lists[file_name_base][3]}</th>'
                        file_urls += '</tr>\n'


    return file_urls

def cve_search():
    """CVE test body

    :return:
    """

    global log_file_handler
    global total_cve_lists

    # for CVE file list reference link
    html_template = """
    <html>
        <head><h1>Indie CVE Vulnerabilities Report For Project REPLACE_THIS_WITH_PROJECT_NAME</h1></head>
        <style>
            table, th, td {
                border:1px solid black;
            }
        </style>
        <style>
            b { 
              font-weight: bold;
            }
        </style>
        <body>
            <p>WARNING: There are total <REPLACE THIS FOR VULNERABILITIES NUMBER> new vulnerabilities reported
            since last past_days days (REPLACE THIS WITH DAYS) and not reported in last searching!</p>
            <p><b>Initial vendors/products keywords</b></p>
            REPLACE THIS FOR VENDORS/PRODUCTS KEYWORDS
            <p><b>Formatted vendors/products keywords</b></p>
            REPLACE THIS FOR FORMATTED VENDORS/PRODUCTS KEYWORDS
            <p><b>CVE file Links</b></p>
            <table style="width:100%">
                  <tr>
                    <th>CVE ID On cve.mitre.org</th>
                    <th>Source CVE ID JSON File On Github</th>
                    <th>Vulnerabilities Reason Listed</th>
                    <th>New/Updated</th>
                    <th>Data Version</th>
                  </tr>
                  <REPLACE THIS FOR FILES LINK>
            </table>
        </body>
    </html>
    """


    actual_report_name = f'{CVE_REPORT_FILENAME_PRE}_{project_name}.txt'

    # Open the HTML file
    report_link_html_fd = open(f'{CVE_REPORT_FILENAME_PRE}_{project_name}.html', 'w+')

    # update local the database from github
    do_update_latest_cve_database(cve_list_repo_url)

    cve_log(banner)

    cve_log(f'CVE report name: {actual_log_name}')

    cve_log(f'Track CVE database back to date {past}')
    cve_log('Formatted searched vendor products:')
    cve_log(pprint.pformat(formatted_vendor_products))

    # parse the record in cve database
    file_urls = browse_json_files_and_parse()

    # update html with updated local CVE file links
    html_template = html_template.replace('REPLACE_THIS_WITH_PROJECT_NAME', project_name)
    html_template = html_template.replace('<REPLACE THIS FOR FILES LINK>', file_urls)
    html_template = html_template.replace('<REPLACE THIS FOR VULNERABILITIES NUMBER>', str(len(total_cve_lists)))
    html_template = html_template.replace('past_days', str(past_days))
    html_template = html_template.replace('REPLACE THIS WITH DAYS', past.strftime('%d/%m/%y %H:%M:%S.%f'))

    v_p = ''
    for v, ps in vendor_products_keywords.items():
        v_p += f'Vendor: {v}, products: '
        for p in ps.split(','):
            v_p += p + ', '
        v_p += '<br>'

    f_v_p = ''
    for v, ps in formatted_vendor_products.items():
        f_v_p += f'Vendor: {v}, products: '
        for p in ps:
            f_v_p += p + ', '
        f_v_p += '<br>'

    html_template = html_template.replace('REPLACE THIS FOR VENDORS/PRODUCTS KEYWORDS', v_p)
    html_template = html_template.replace('REPLACE THIS FOR FORMATTED VENDORS/PRODUCTS KEYWORDS', f_v_p)
    report_link_html_fd.write(html_template)
    report_link_html_fd.close()

    # total_cve_lists includes updated CVE database we are interesting
    if total_cve_lists:
        formatted_cve_lists = pprint.pformat(total_cve_lists)
        cve_log(f'Test report name: {actual_report_name}')
        cve_log('')
        cve_log('')
        cve_log(f'--------------------------------------------------------')
        cve_log(f'CVS updated report for our vendors/products keywords:')
        cve_log(f'========================================================')
        cve_log(f'!! There are total {len(total_cve_lists)} vulnerabilities reported since last {past_days} days')
        cve_log(f'!! (from {str(past)}) for our vendors/products keywords')
        cve_log('')
        cve_log(formatted_cve_lists)
        cve_log(f'**************************************************************')
        cve_log(f'CVS updated short report for our vendors/products products:')
        cve_log(f'=============================================================')
        cve_log(f'!! There are total {len(total_cve_lists)} vulnerabilities reported since last {past_days} days')
        cve_log(f'!! (from {str(past)}) for our vendors/products keywords')
        cve_log('')
        formatted_cve_short_lists = pprint.pformat(total_cve_lists.keys())
        for cve_id in total_cve_lists.keys():
            cve_log(cve_id)

        with open(actual_report_name, "w", encoding='utf-8') as report_file_handler:
            report_file_handler.write(formatted_cve_lists)

        cve_log('Done!')

        cve_log('Found. Found vulnerability related to our keywords')
        return True
    else:
        cve_log(f'Not found. There is no any vulnerability found since past {past_days} days')
        return False
            
def get_timestamp_for_cve_report_folder(folder_url):
    """

    :param folder_url:
    :return:
    """

    folder_url_folder_name = folder_url.split(cve_storage_url)[1]
    folder_url_folder_name = folder_url_folder_name.replace('\\', '')
    folder_url_folder_name = folder_url_folder_name.replace('/', '')
    return folder_url_folder_name

def found_last_CVE_report_timestamp():
    """

    :return: None - no last report found (it's fresh folder
             <timestamp> - timestamp for last CVE report
    """

    latest_cve_record_folder = None
    latest_cve_record_folder_name = None
    saved_records_sub_folders = [x[0] for x in os.walk(cve_storage_url)]
    # If this is a fresh folder, ignore this step
    if len(saved_records_sub_folders) > 1:
        # find the last record saved by past days ago
        for saved_cve_record_folder in saved_records_sub_folders:
            if saved_cve_record_folder != cve_storage_url:
                # Note that folder named is timestamp so we can compare 2 folder names like time
                if cve_storage_folder == saved_cve_record_folder:
                    continue
                # if last report not found before, use this one as last report and get timestamp on it
                if not latest_cve_record_folder:
                    latest_cve_record_folder = saved_cve_record_folder
                    # retrieve last timestamp by its file name
                    latest_cve_record_folder_name = get_timestamp_for_cve_report_folder(latest_cve_record_folder)
                else:
                    # get folder name without path only
                    saved_cve_record_folder_name = get_timestamp_for_cve_report_folder(saved_cve_record_folder)
                    # retrieve last timestamp by its file name
                    if datetime.strptime(saved_cve_record_folder_name, "%Y-%m-%d_%H.%M.%S") > \
                            datetime.strptime(latest_cve_record_folder_name, "%Y-%m-%d_%H.%M.%S"):
                        latest_cve_record_folder = saved_cve_record_folder
                    latest_cve_record_folder_name = get_timestamp_for_cve_report_folder(latest_cve_record_folder)
    return latest_cve_record_folder_name

if __name__ == '__main__':
    usage_help = \
    """To run it:
    cve_search.py [-h] [-a APPENDED_LIST] [-r USE_THIS_LIST] [-d PAST_DAYS] [-p project]

    optional arguments:
        -h, --help: show this help message and exit
        -a, --add: append this vendor/products keyword item to the list in indie_cve_config.ini
        -r, --replace: overwrite existing the list in indie_cve_config.ini with this 
                       vendor/products keyword item
        -p --project: project name which is defined in .ini. Keywords in this project will be used
        
    example: cve_search.py -h
             cve_search.py -a Cadence:XTENSA,lx8 -d 7
             cve_search.py -r Cadence:XTENSA,lx8 -d 1000
             cve_search.py -p ind880
    To use default options in indie_cve_config.ini, without any parameters in the command line.

    Note: 
        1. Option '-a' is to append this vendor/products keyword item to the list in indie_cve_config.ini;
        2. Option '-r' is to overwrite existing the list in indie_cve_config.ini with this vendor/products
           keyword  item. That means the vendors/products list in indie_cve_config.ini will be ignored.
        3. Option '-p' is for project name. It should be existing in indie_cve_config.ini. 
    """

    # get current timestamp
    present_time = datetime.now()

    current_date_string = f'{present_time:%Y-%m-%d_%H.%M.%S}'

    use_this_vendor_products_list = False
    add_option = {}
    replace_option = {}
    days = None
    project_name = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:r:d:p:", ["add=", "replace=", "days=", "project="])
    except getopt.GetoptError:
        print(usage_help)
        sys.exit(2)
    # -a and -r entered same time?
    for opt, arg in opts:

        if opt == '-h':
            print(usage_help)
            sys.exit()
        elif opt in ("-a", "--add"):
            add_option[arg.split(':')[0]] = [p for p in arg.split(':')[1].split(',')]
            breakpoint()
        elif opt in ("-r", "--replace"):
            replace_option[arg.split(':')[0]] = [p for p in arg.split(':')[1].split(',')]
        elif opt in ("-d", "--days"):
            days = int(arg)
        elif opt in ("-p", "--project"):
            project_name = arg


    # parse config.ini to get options
    # instantiate
    config = ConfigParser()
    # keep cases
    config.optionxform = str
    config.read('indie_cve_config.ini')

    # read values from a section
    if days:
        past_days = days
    else:
        past_days = config.getint('cve', 'past_days')

    cve_list_repo_url = config.get('cve', 'cve_list_repo_url')
    cve_search_site_url = config.get('cve', 'cve_search_site_url')
    cve_root_repo_url = config.get('cve', 'cve_root_repo_url')
    # if there is no project name from the command line, use one defined in .ini
    if project_name:
        if project_name not in config.sections():
            print(f'The project name {project_name} is not found in .ini.')
            sys.exit(2)
    else:
        project_name = config.get('cve', 'for_project')
    cve_storage_url = config.get('cve', 'cve_storage_url')

    cve_storage_folder = f'{cve_storage_url}/{current_date_string}'

    # update default home_folder if existing in indie_cve_conifg.ini
    if 'home_folder' in config.options('cve'):
        home_folder = config.get('cve', 'home_folder')
        cvelistV5_dir = f'{home_folder}/cvelistV5'

    vendor_products_keywords_lower_case = {}

    if replace_option:
        for k, p_v in replace_option.items():
            # remove last one if option is end with comma ','
            if p_v[-1].strip() == '':
                p_v.pop()
            vendor_products_keywords_lower_case[k.lower()] = [v.lower().strip() for v in p_v]
    else:
        vendor_products_keywords = {}
        for option in config.options(project_name):
            vendor_products_keywords[option] = config.get(project_name, option)

        # less sensitive for case.
        for k, p_v in vendor_products_keywords.items():
            p_v = p_v.split(',')
            # remove last one if option is end with comma ','
            if p_v[-1].strip() == '':
                p_v.pop()
            vendor_products_keywords_lower_case[k.lower()] = [v.lower().strip() for v in p_v]

        # if there is newly added vendor/products from the command line, add it.
        # it may overwrite old one of vendor is the same.
        if add_option:
            for k, p_v in add_option.items():
                p_v = p_v.split(',')
                # remove last one if option is end with comma ','
                if p_v[-1].strip() == '':
                    p_v.pop()
                vendor_products_keywords_lower_case[k.lower()] = [v.lower().strip() for v in p_v]

    # format the vendor_products_keywords_lower_case table to extend possible
    # products name. For example, product name "DWC-Ether-QOS" can be written without the '-'.
    # We will use this new dict to be used for searching
    formatted_vendor_products = {}
    all_formatted_products_list = []
    for vendor, products in vendor_products_keywords_lower_case.items():
        updated_products = []
        for product in products:
            updated_products.append(product)
            if ' ' in product:
                updated_products.append(product.replace(' ', '_'))
                updated_products.append(product.replace(' ', '-'))
                updated_products.append(product.replace(' ', ''))
            if '_' in product:
                updated_products.append(product.replace('_', ' '))
                updated_products.append(product.replace('_', '-'))
                updated_products.append(product.replace('_', ''))
            if '-' in product:
                updated_products.append(product.replace('-', ' '))
                updated_products.append(product.replace('-', '_'))
                updated_products.append(product.replace('-', ''))
            all_formatted_products_list += updated_products
        formatted_vendor_products[vendor] = updated_products

    timestamp_for_last_report = found_last_CVE_report_timestamp()
    if timestamp_for_last_report:
        last_timestamp = datetime.strptime(timestamp_for_last_report, '%Y-%m-%d_%H.%M.%S')
    else:
        last_timestamp = None

    # track back past days
    past = present_time - timedelta(days=past_days)

    cve_status = False
    actual_log_name = f'{CVE_LOG_FILENAME_PRE}_{project_name}.txt'
    with open(actual_log_name, "w", encoding='utf-8') as log_file_handler:
        past_timestamp_string = past.strftime('%Y-%m-%d %H:%M:%S')
        past_timestamp_string = f'The timestamp for past days: {past_timestamp_string}'
        cve_log(past_timestamp_string)

        # if last_timestamp is earlier than we expected, we need to use last_timestamp as start point for
        # this new scanning
        if last_timestamp:
            last_timestamp_string = last_timestamp.strftime('%Y-%m-%d %H:%M:%S')
            last_timestamp_string = f'The timestamp for last report: {last_timestamp_string}'
            cve_log(last_timestamp_string)

            if last_timestamp < past:
                cve_log(f'As last timestamp {last_timestamp_string} is earlier, we will use it to start scanning...')
                past = last_timestamp
            else:
                cve_log(f'As last timestamp {last_timestamp_string} is newer, we will'
                        'use past timestamp {past} to start scanning...')
                cve_log('Warning: this may create duplicated CVE IDs in report!')
        else:
            cve_log(f'As we do not have any last report, we will start from {past_timestamp_string} to scan...')

        cve_status = cve_search()

    log_file_handler.close()

    # save log and reports to storage
    if not Path(cve_storage_folder).exists():
        os.mkdir(cve_storage_folder)

    f1 = f'{CVE_LOG_FILENAME_PRE}_{project_name}.txt'
    f2 = f'{CVE_REPORT_FILENAME_PRE}_{project_name}.txt'
    f3 = f'{CVE_REPORT_FILENAME_PRE}_{project_name}.html'
    shutil.copyfile(f1, cve_storage_folder + '/' + f1)
    if Path(f2).exists():
        shutil.copyfile(f2, cve_storage_folder + '/' + f2)
    shutil.copyfile(f3, cve_storage_folder + '/' + f3)

    if cve_status:
        sys.exit(1)
    else:
        sys.exit(0)