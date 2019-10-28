from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import ActionChains
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from python3_anticaptcha import NoCaptchaTaskProxyless

from urllib import parse

import time
import json
import requests

def get_token(adUrl, cookieText):

    headers = {
        'sec-fetch-mode': 'cors',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36',
        'accept': '*/*',
        'referer': 'https://www.kijiji.ca/v-plumber/winnipeg/cost-effective-residential-sewer-line-drain-cleaning-service/1380571584',
        'authority': 'www.kijiji.ca',
        'cookie': cookieText,
        'sec-fetch-site': 'same-origin',
    }

    response = requests.head('https://www.kijiji.ca/j-token-gen.json', headers=headers)
    print(response)
    print(response.headers)

    return response.headers['X-Ebay-Box-Token']


def send_message(adUrl, adId, captchaResponse, cookieText, ebayToken):

    headers = {
        'sec-fetch-mode': 'cors',
        'origin': 'https://www.kijiji.ca',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36',
        'content-type': 'application/x-www-form-urlencoded',
        'cookie': cookieText,
        'x-ebay-box-token': ebayToken,
        'accept': '*/*',
        'referer': adUrl,
        'authority': 'www.kijiji.ca',
        'sec-fetch-site': 'same-origin',
    }

    data = {
    'fromName': 'Megan Fox',
    'message': 'Hey there! How are you!.',
    # 'externalAdSource': 'null',
    'sendCopyToSender': 'false',
    'recaptchaResponse': captchaResponse,
    'adId': adId,
    'emailRequiresVerification': 'false',
    'from': 'cabot@yopmail.com'
    }

    response = requests.post('https://www.kijiji.ca/j-contact-seller.json', headers=headers, data=data)
    print(response.content)
    print(response)


def process_browser_log_entry(entry):
    response = json.loads(entry['message'])['message']
    return response

# constants
ANTICAPTCHA_KEY = "***REMOVED***"
PAGE_URL = 'https://www.kijiji.ca/v-plumber/winnipeg/cost-effective-residential-sewer-line-drain-cleaning-service/1380571584'
AD_ID = PAGE_URL.split('/')[-1]

# define the capabilities
caps = DesiredCapabilities.CHROME
caps['goog:loggingPrefs'] = {'performance': 'ALL'}

# define Chrome options
options = webdriver.ChromeOptions()
options.add_argument("--disable-web-security")
options.add_argument("--allow-running-insecure-content")

driver = webdriver.Chrome(desired_capabilities=caps, chrome_options=options)

parentUrl = "https://www.kijiji.ca"
driver.get(parentUrl + '/t-login.html')

emailBox = driver.find_element_by_id('LoginEmailOrNickname')
passwordBox = driver.find_element_by_id('login-password')
loginButton = driver.find_element_by_id('SignInButton')

emailBox.send_keys('cabot@yopmail.com')
passwordBox.send_keys('cabot#123')
loginButton.click()

time.sleep(5)

driver.get(PAGE_URL)

time.sleep(5)

browser_log = driver.get_log('performance') 
events = [process_browser_log_entry(entry) for entry in browser_log]
events = [event for event in events if 'Network.requestWillBeSent' in event['method']]

payloadURL = ''

time.sleep(5)

for singleEvent in events:
    try:
        currentURL = singleEvent['params']['documentURL']
        if currentURL.startswith("https://www.google.com/recaptcha"):
            payloadURL = currentURL
            break
    except:
        pass

print(payloadURL)
SITE_KEY = parse.parse_qs(parse.urlsplit(payloadURL).query)['k'][0]
print(SITE_KEY)

cookieString = ""

allCookies = driver.get_cookies()
for singleCookie in allCookies:
    cookieString += (singleCookie['name'] + "=" + singleCookie['value'] + "; ")

print(cookieString)

ebayToken = get_token(PAGE_URL, cookieString)
time.sleep(10)

# SITE_KEY = driver.execute_script("document.getElementById('recaptcha-token').value")
# rcElement = driver.find_element_by_id("recaptcha-token")
# SITE_KEY = rcElement.get_attribute("value")
# print(SITE_KEY)

user_answer = NoCaptchaTaskProxyless.NoCaptchaTaskProxyless(anticaptcha_key = ANTICAPTCHA_KEY)\
                .captcha_handler(websiteURL=PAGE_URL,
                                 websiteKey=SITE_KEY)

# print(user_answer)
gcaptchaResponse = user_answer['solution']['gRecaptchaResponse']
print(gcaptchaResponse)

send_message(PAGE_URL, AD_ID, gcaptchaResponse, cookieString, ebayToken)

# messageBox = driver.find_element_by_id('message')
# messageBox.send_keys(Keys.CONTROL, 'a')
# messageBox.send_keys('Hey there!')

# driver.execute_script('document.getElementById("g-recaptcha-response").innerHTML = "%s"' % gcaptchaResponse)
# # driver.find_element_by_id('g-recaptcha-response').send_keys(gcaptchaResponse)

# # driver.find_element_by_xpath('//*[@id="vip-body"]/div[6]/div[2]/div/form/div[4]/button').click()
# time.sleep(2)
# # foo = driver.find_element_by_id('g-recaptcha-response')
# # print(foo.get_attribute('name'))
# # foo.send_keys(gcaptchaResponse)

# time.sleep(5)

# print(driver.find_element_by_id('g-recaptcha-response').get_attribute('value'))

# form = driver.find_element_by_class_name('form-4168487082')
# form.submit()