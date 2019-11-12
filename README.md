# Kijiji Spider

## Capabilities
1. Search by _keyword_ (and optionally _category_) on Kijiji and pick up ad URLs
2. Pick up __Business Name__, __Phone Number__, __Person Name__, __Person Email__ from the ad page
3. Send customized message through the _message box_ to the business person from the page*
4. Saving the information and message sent status to CSV

*Requires AntiCaptcha API Key

## Setup
The script uses Selenium for the purpose. __Chromedriver__ should be correctly [configured](https://chromedriver.chromium.org/) in PATH.

The dependencies for the script should be installed as:
```
pip3 install -r requirements.txt
```

The running of this script requires a Kijiji account and optionally AntiCaptcha API Key for the message sending. An `.env` file should exist in the root directory with the following configurations:
```
ANTICAPTCHA_KEY=
KIJIJI_EMAIL=
KIJIJI_PASSWORD=
```

## Getting Started
```
python3 scraper.py <numberOfResultsRequired> <searchQuery> <searchCategory>
```
