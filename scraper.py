import sys
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import ActionChains
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

from python3_anticaptcha import NoCaptchaTaskProxyless

import re
import codecs
import csv
import time
import requests
import json
from urllib import parse

import uuid
import timeout_decorator

# function for getting the ebay token
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

# function for sending the message using requests
def send_message(adUrl, adId, captchaResponse, cookieText, ebayToken, uniqueID):

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
    'fromName': 'Harry',
    'message': 'Hey there! How are you! ' + uniqueID,
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

# helper function for processing the browser logs
def process_browser_log_entry(entry):
    response = json.loads(entry['message'])['message']
    return response

# function for getting the SITE_KEY from the network logs
@timeout_decorator.timeout(60)
def get_recaptcha_site_key(driver):
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

	# print(payloadURL)
	siteKey = parse.parse_qs(parse.urlsplit(payloadURL).query)['k'][0]
	print(siteKey)

	return siteKey

# function for getting the site's cookies in the required syntax
@timeout_decorator.timeout(60)
def get_cookie_string(driver):
	cookieString = ""

	allCookies = driver.get_cookies()
	for singleCookie in allCookies:
		cookieString += (singleCookie['name'] + "=" + singleCookie['value'] + "; ")

	print(cookieString)
	return cookieString

# function for using anticaptcha solver to solve the captcha - timeout in 200s
@timeout_decorator.timeout(200)
def get_captcha_response(antiCaptchaKey, PageUrl, SiteKey):
	user_answer = NoCaptchaTaskProxyless.NoCaptchaTaskProxyless(anticaptcha_key = antiCaptchaKey)\
					.captcha_handler(websiteURL=PageUrl,
									websiteKey=SiteKey)

	# print(user_answer)
	gcaptchaResponse = user_answer['solution']['gRecaptchaResponse']
	print(gcaptchaResponse)
	return gcaptchaResponse

# function for writing to file
def writeToFile(table):
	# csvfile = codecs.open('output.csv', 'w', 'utf_8_sig')
	csvfile = open('output.csv', 'a')
	writer = csv.writer(csvfile)
	writer.writerows(table)
	csvfile.close()

# function for logging in to Kijiji
def login(driver, email, password):
	LFLAG = False
	for retry in range(5):
		try:
			driver.get(parentUrl + '/t-login.html')
			LFLAG = True
			break
		except:
			continue
	if not LFLAG:
		sys.exit()

	emailBox = driver.find_element_by_id('LoginEmailOrNickname')
	passwordBox = driver.find_element_by_id('login-password')
	loginButton = driver.find_element_by_id('SignInButton')

	emailBox.send_keys(email)
	passwordBox.send_keys(password)
	loginButton.click()

# program starts
ANTICAPTCHA_KEY = "***REMOVED***"
KIJIJI_EMAIL = 'cabot@yopmail.com'
KIJIJI_PASSWORD = 'cabot#123'

parentUrl = "https://www.kijiji.ca"

# define the capabilities
caps = DesiredCapabilities.CHROME
caps['goog:loggingPrefs'] = {'performance': 'ALL'}

# define Chrome options
options = webdriver.ChromeOptions()
options.add_argument("--disable-web-security")
options.add_argument("--allow-running-insecure-content")

driver = webdriver.Chrome(desired_capabilities=caps, chrome_options=options)

login(driver, KIJIJI_EMAIL, KIJIJI_PASSWORD)
time.sleep(5)

resultsWanted = int(sys.argv[1])
print("Getting approximately {0} results for each query".format(resultsWanted))

for searchQuery in sys.argv[2:]:
	print("Starting search for {0}".format(searchQuery))

	FFLAG = False
	for retry in range(5):
		try:
			driver.get(parentUrl)
			FFLAG = True
			break
		except:
			continue

	if not FFLAG:
		sys.exit()

	# put the query into the search box
	driver.execute_script("document.getElementById('SearchKeyword').value = '{0}'".format(searchQuery))

	# wait for the details to be entered by the user and pressing the search button
	element = WebDriverWait(driver, 600).until(
		EC.presence_of_element_located((By.XPATH, '//*[@id="mainPageContent"]/div[3]/div[3]/div/div[1]/div[2]'))
	)
	print("Moved to search results page")

	pageIndex = 1
	adUrls = []

	while(True):
		currentPage = driver.current_url
		currentPageList = currentPage.split("/")

		# understanding the end of pagination
		checkerPageList = currentPageList[:-2] + ["page-" + str(pageIndex - 1)] + currentPageList[-1:]
		checkerPage = '/'.join(checkerPageList)

		if (checkerPage == currentPage):
			break

		# aggregating all the results in the current page
		allResults = driver.find_elements_by_tag_name("table")
		for result in allResults:
			adUrl = result.get_attribute("data-vip-url")
			if adUrl is not None:
				adUrls.append(parentUrl + adUrl)

		allResults1 = driver.find_elements_by_css_selector('div.search-item')
		for result in allResults1:
			adUrl = result.get_attribute("data-vip-url")
			if adUrl is not None:
				adUrls.append(parentUrl + adUrl)

		# move to the next page
		pageIndex += 1
		newPageList = currentPageList[:-1] + ["page-" + str(pageIndex)] + currentPageList[-1:]
		newPage = '/'.join(newPageList)

		SFLAG = False
		for retry in range(5):
			try:
				driver.get(newPage)
				SFLAG = True
				break
			except:
				continue

		if not SFLAG:
			pageIndex += 1
			continue

		urlCollectedCount = len(adUrls)
		print("Collected {0} URLs".format(urlCollectedCount))

		if urlCollectedCount >= resultsWanted:
			break

	print("Collected all ad URLs")

	table = []
	adUrlCount = len(adUrls)
	print(adUrlCount)

	for adIndex in range(len(adUrls)):

		payloadUrl = adUrls[adIndex]
		print(payloadUrl)
		AD_ID = payloadUrl.split('/')[-1]

		TFLAG = False
		for retry in range(5):
			try:
				# driver.execute_script('window.open()')
				# driver.switch_to_window(driver.window_handles[adIndex + 1])
				driver.get(payloadUrl)
				TFLAG = True
				break
			except Exception as e:
				print(e)
				continue

		if not TFLAG:
			continue

		time.sleep(10)
		uniqueID = str(uuid.uuid1()).split('-')[0]

		try:
			SITE_KEY = get_recaptcha_site_key(driver)
			COOKIE_STRING = get_cookie_string(driver)
			EBAY_TOKEN = get_token(payloadUrl, COOKIE_STRING)

			GCAPTCHA_RESPONSE = get_captcha_response(ANTICAPTCHA_KEY, payloadUrl, SITE_KEY)
			send_message(payloadUrl, AD_ID, GCAPTCHA_RESPONSE, COOKIE_STRING, EBAY_TOKEN, uniqueID)
		except Exception as e:
			print(e)
			print("Message sending failed / timeout!")

		time.sleep(5)

		allText = ""
		allParagraphs = driver.find_elements_by_tag_name("p")
		for p in allParagraphs:
			allText += p.text

		# pick the business name from the ad
		businessName = driver.find_element_by_xpath('//*[@id="ViewItemPage"]/div[5]/div[1]/div[1]/div/h1').text
		print(businessName)

		allText += ("\n" + businessName)

		try:
			messageBox = driver.find_element_by_id('message')
			messageBox.send_keys(Keys.CONTROL, 'a')
			messageBox.send_keys('Hey there!')
			# messageBox.submit()
		except Exception as e:
			print(e)

		# pick the phone number from the ad
		phoneNumberRegex = re.compile(r'((\()?\d\d\d(\)?)(-| )?(\d\d\d(-| )?\d\d\d\d))')
		regexGrouper = phoneNumberRegex.search(allText)

		try:
			allNumbersCaptured = list(regexGrouper.groups())
			allNumbersCaptured = [el for el in allNumbersCaptured if el is not None]
			allNumbersCaptured.sort(key = lambda s: len(s))
			phoneNumber = allNumbersCaptured[-1]
		except:
			phoneNumber = ""
			pass

		print(phoneNumber)

		# pick the person name from the ad
		try:
			personName = driver.find_element_by_xpath('//*[@id="vip-body"]/div[6]/div[3]/div/div[1]/div/a').text
		except Exception as e:
			personName = ""
			pass

		print(personName)

		# pick up the email from the ad
		allEmailsCaptured = re.findall(r'\S+@\S+', allText)
		try:
			allEmailsCaptured = [el for el in allEmailsCaptured if el is not None]
			allEmailsCaptured.sort(key = lambda s: len(s))     
			personEmail = allEmailsCaptured[-1]

		except Exception as e:
			personEmail = ""
			pass

		print(personEmail)

		table.append([businessName, phoneNumber, personName, personEmail, uniqueID])

		if (adUrlCount % 10 == 0):
			writeToFile(table)
			table = []

		adUrlCount -= 1

		# driver.switch_to_window(driver.window_handles[0])