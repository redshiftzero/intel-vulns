# intel-vulns

This is a utility for scraping Intel Security Center to get vulnerability data in a structured format

I wrote this to grab vulnerability data from 2019-11-12 for https://github.com/freedomofpress/securedrop/issues/4992

## Usage

```
virtualenv --python python3 .venv
source .venv/bin/activate
pip install -r requirements.txt
# Edit RELEASE_DATE in scrape.py if you
# want to grab vulns from a day that is not 2019-11-12
python scrape.py
```