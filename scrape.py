from bs4 import BeautifulSoup
from datetime import datetime
from dateutil import parser
import pandas as pd
from typing import Optional
import requests
from urllib.parse import urljoin


RELEASE_DATE = datetime(2019, 11, 12)

BASE_URL = 'https://www.intel.com'
INTEL_SECURITY_CENTER_INDEX = '/content/www/us/en/security-center/default.html'

COLUMN_ADVISORY_NUM = 1
COLUMN_RELEASE_DATE_NUM = 3


def extract_vulns(df: pd.DataFrame) -> pd.DataFrame:
    cve_ids = []
    cvss_base_scores = []
    # TODO: Would be cool to parse the CVSS vector, turns out there is a lib to do so
    # https://pypi.org/project/cvss/
    cvss_vectors = []
    descriptions = []
    advisory_urls = []
    advisory_ids = []
    cve_urls = []

    for row in df.iterrows():
        advisory_url = urljoin(BASE_URL, row[1]['Advisory URL'])
        advisory_id = row[1]['Advisory Number']
        individual_advisory_pg = requests.get(advisory_url)
        advisory_soup = BeautifulSoup(individual_advisory_pg.content, "html.parser")
        paragraphs = advisory_soup.find_all("p")

        # Each vuln begins with a paragraph beginning with 'CVEID'
        vulnerabilities_indices = [i for i in range(len(paragraphs)) if 'CVEID' in paragraphs[i].text]
        for vuln_id in vulnerabilities_indices:
            cve_id = paragraphs[vuln_id].find("a").text
            cve_url = paragraphs[vuln_id].find("a").attrs['href']

            description = paragraphs[vuln_id + 1].text.lstrip("Description: ")

            num_desc_paragraphs = 1

            # There may be an additional paragraph after the description.
            keep_going = True
            while keep_going:
                try:
                    cvss_score_and_categorial = paragraphs[vuln_id + num_desc_paragraphs + 1].text.split(":")[1].strip()
                    cvss_base_score = cvss_score_and_categorial.split()[0]
                    cvss_base_categorical = cvss_score_and_categorial.split()[1]  # i.e. Low, Medium, High, Critical
                    cvss_vector = paragraphs[vuln_id + num_desc_paragraphs + 2].find("a").text
                    keep_going = False
                except IndexError:
                    num_desc_paragraphs += 1

            cve_ids.append(cve_id)
            cvss_base_scores.append(cvss_base_score)
            descriptions.append(description)
            cvss_vectors.append(cvss_vector)
            cve_urls.append(cve_url)
            advisory_urls.append(advisory_url)
            advisory_ids.append(advisory_id)

    df = pd.DataFrame({
        'CVE ID': cve_ids,
        'CVSS Vector': cvss_vectors,
        'CVSS Base Score': cvss_base_scores,
        'Description': descriptions,
        'Advisory URL': advisory_urls,
        'Advisory ID': advisory_ids,
        'CVE URL': cve_urls,
    })
    return df


def parse_index() -> pd.DataFrame:
    main_advisory_pg = requests.get(urljoin(BASE_URL, INTEL_SECURITY_CENTER_INDEX))
    index_soup = BeautifulSoup(main_advisory_pg.content, "html.parser")
    security_advisories = index_soup.find_all("tr", class_="data")
    release_names, release_nums, release_dates, release_urls = [], [], [], []
    for advisory in security_advisories:
        advisory_link = advisory.find("a")
        release_url = urljoin(BASE_URL, advisory_link.attrs['href'])
        release_name = advisory_link.text
        release_num = advisory.find_all("td")[COLUMN_ADVISORY_NUM].text.strip()
        try:
            release_date = parser.parse(advisory.find_all("td")[COLUMN_RELEASE_DATE_NUM].text.strip())
        except parser._parser.ParserError:
            # This can happen if there is a misspelling in e.g. the month.
            # TODO: Would be nice to attempt to fix.
            release_date = None

        release_names.append(release_name)
        release_nums.append(release_num)
        release_dates.append(release_date)
        release_urls.append(release_url)

    df = pd.DataFrame({
        'Advisories': release_names,
        'Advisory Number': release_nums,
        'Advisory URL': release_urls,
        'Release Date': release_dates,
    })
    return df


if __name__ == '__main__':
    df_index = parse_index()

    # Select relevant advisories
    # TODO: Would be cool to have a CLI
    df_selected = df_index[df_index['Release Date'] == RELEASE_DATE]

    df_vulns = extract_vulns(df_selected)
    df_vulns.to_csv('intel_vulns.csv', index=False)
