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
import os
import codecs
import csv
import time
import requests
import json
from urllib import parse

import uuid
import timeout_decorator

import threading
from dotenv import load_dotenv
load_dotenv()

# function for getting the ebay token specific to user
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
	return response.headers['X-Ebay-Box-Token']

# function 1 for sending the message using requests
def send_message_1(adUrl, adId, captchaResponse, cookieText, ebayToken, uniqueID, externalSourceId, channelId, fromEmail):
	print("Trying first POST method")

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
	'message': 'Hey there! Are you available? Thanks, please do reach back! ' + uniqueID,
	'externalAdSource': channelId,
	'sendCopyToSender': 'true',
	'recaptchaResponse': captchaResponse,
	'adId': adId,
	'emailRequiresVerification': 'false',
	'from': fromEmail
	}

	response = requests.post('https://www.kijiji.ca/j-contact-seller-cas.json?channelId=' + channelId, headers=headers, data=data)
	print(response.json())
	return response.json()

# function 2 for sending message using requests
def send_message_2(adUrl, adId, captchaResponse, cookieText, ebayToken, uniqueID, externalSourceId, channelId, fromEmail):
	print("Trying second POST method")

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
	'message': 'Hey there! Are you available? Please do reach out, thank you! ' + uniqueID,
	'sendCopyToSender': 'true',
	'recaptchaResponse': captchaResponse,
	'adId': adId,
	# 'initialMessageIds': '1,2,3',
	'emailRequiresVerification': 'false',
	'from': fromEmail
	}

	response = requests.post('https://www.kijiji.ca/j-contact-seller.json', headers=headers, data=data)
	print(response.json())
	return response.json()

# function 3 for sending message using requests
def send_message_3(adUrl, adId, captchaResponse, cookieText, ebayToken, uniqueID, externalSourceId, channelId, fromEmail):
	print("Trying third POST method")

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
	'message': 'Hey there! Are you available? Please do reach out, thanks! ' + uniqueID,
	'sendCopyToSender': 'true',
	'recaptchaResponse': captchaResponse,
	'adId': adId,
	'initialMessageIds': '1,2,3',
	'emailRequiresVerification': 'false',
	'from': fromEmail
	}

	response = requests.post('https://www.kijiji.ca/j-contact-seller.json', headers=headers, data=data)
	print(response.json())
	return response.json()

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

	# time.sleep to be replaced by waitTillPageLoaded
	time.sleep(5)

	for singleEvent in events:
		try:
			currentURL = singleEvent['params']['documentURL']
			if currentURL.startswith("https://www.google.com/recaptcha"):
				payloadURL = currentURL
				break
		except:
			pass

	siteKey = parse.parse_qs(parse.urlsplit(payloadURL).query)['k'][0]
	return siteKey

# function for getting the site's cookies in the required syntax
@timeout_decorator.timeout(60)
def get_cookie_string(driver):
	cookieString = ""

	allCookies = driver.get_cookies()
	for singleCookie in allCookies:
		cookieString += (singleCookie['name'] + "=" + singleCookie['value'] + "; ")

	return cookieString

# function for using anticaptcha solver to solve the captcha - timeout in 200s
@timeout_decorator.timeout(200)
def get_captcha_response(antiCaptchaKey, PageUrl, SiteKey):
	user_answer = NoCaptchaTaskProxyless.NoCaptchaTaskProxyless(anticaptcha_key = antiCaptchaKey)\
					.captcha_handler(websiteURL=PageUrl,
									websiteKey=SiteKey)

	gcaptchaResponse = user_answer['solution']['gRecaptchaResponse']
	return gcaptchaResponse

# function for writing to file
def writeToFile(table):
	csvfile = open('output' + UID + '.csv', 'a')
	writer = csv.writer(csvfile)
	writer.writerows(table)
	csvfile.close()

# function for visiting a page using chromedriver
def visitPage(driver, pageURL):
	LFLAG = False
	for _retry in range(5):
		try:
			driver.get(pageURL)
			LFLAG = True
			break
		except:
			continue
	if not LFLAG:
		sys.exit()

	return driver

# function to check if the ad is of resume (application) type
def isAdResumeType(driver):
	try:
		fileBoxArray = driver.find_elements_by_id('fileList')
		if len(fileBoxArray) == 0:
			return False
		return True
	except:
		return False

# function for extracting all the text as blob out of the ad page
def extractText(driver):
	allText = ""
	allParagraphs = driver.find_elements_by_tag_name("p")
	for p in allParagraphs:
		allText += p.text

	return allText

# function for picking up the business name from the ad page
def getBusinessName(driver):
	businessName = driver.find_element_by_xpath('//*[@id="ViewItemPage"]/div[5]/div[1]/div[1]/div/h1').text
	return businessName

# function for picking up the phone number from the ad page
def getPhoneNumber(allText):
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

	return phoneNumber

# function for picking up the person name from the ad page
def getPersonName(driver):
	try:
		personName = driver.find_element_by_xpath('//*[@id="vip-body"]/div[6]/div[3]/div/div[1]/div/a').text
	except:
		personName = ""
		pass

	return personName

# function for picking up the person email from the ad page
def getPersonEmail(allText):
	allEmailsCaptured = re.findall(r'\S+@\S+', allText)

	try:
		allEmailsCaptured = [el for el in allEmailsCaptured if el is not None]
		allEmailsCaptured.sort(key = lambda s: len(s))     
		personEmail = allEmailsCaptured[-1]
	except:
		personEmail = ""
		pass

	return personEmail

# function for logging in to Kijiji
def login(driver, email, password):
	driver = visitPage(driver, parentUrl + '/t-login.html')

	emailBox = driver.find_element_by_id('LoginEmailOrNickname')
	passwordBox = driver.find_element_by_id('login-password')
	loginButton = driver.find_element_by_id('SignInButton')

	emailBox.send_keys(email)
	passwordBox.send_keys(password)
	loginButton.click()

	return driver

# driver function for sending message to the customer
def sendMessageDriver(driver, payloadUrl, ANTICAPTCHA_KEY, msgStatus, uniqueID, externalSourceId, channelId, fromEmail):
	try:
		SITE_KEY = get_recaptcha_site_key(driver)
		COOKIE_STRING = get_cookie_string(driver)
		EBAY_TOKEN = get_token(payloadUrl, COOKIE_STRING)
		GCAPTCHA_RESPONSE = get_captcha_response(ANTICAPTCHA_KEY, payloadUrl, SITE_KEY)

		try:
			messageSendingResponse = send_message_2(payloadUrl, AD_ID, GCAPTCHA_RESPONSE, COOKIE_STRING, EBAY_TOKEN, uniqueID, externalSourceId, channelId, fromEmail)
		except Exception as e:
			try:
				messageSendingResponse = send_message_1(payloadUrl, AD_ID, GCAPTCHA_RESPONSE, COOKIE_STRING, EBAY_TOKEN, uniqueID, externalSourceId, channelId, fromEmail)
			except:
				messageSendingResponse = send_message_3(payloadUrl, AD_ID, GCAPTCHA_RESPONSE, COOKIE_STRING, EBAY_TOKEN, uniqueID, externalSourceId, channelId, fromEmail)

		messageSendingStatus = messageSendingResponse["status"]

		if messageSendingStatus == 'ERROR':
			messageSendingResponse = send_message_1(payloadUrl, AD_ID, GCAPTCHA_RESPONSE, COOKIE_STRING, EBAY_TOKEN, uniqueID, externalSourceId, channelId, fromEmail)
			messageSendingStatus = messageSendingResponse["status"]

		if messageSendingStatus == 'ERROR':
			messageSendingResponse = send_message_3(payloadUrl, AD_ID, GCAPTCHA_RESPONSE, COOKIE_STRING, EBAY_TOKEN, uniqueID, externalSourceId, channelId, fromEmail)
			messageSendingStatus = messageSendingResponse["status"]

		if messageSendingStatus == 'OK':
			msgStatus = True

	except Exception as e:
		_exc_type, _exc_obj, exc_tb = sys.exc_info()
		print("Error occured on ", end="")
		print(exc_tb.tb_lineno)
		print(e)

	return msgStatus, driver

# program starts
ANTICAPTCHA_KEY = os.getenv('ANTICAPTCHA_KEY')
KIJIJI_EMAIL = os.getenv('KIJIJI_EMAIL')
KIJIJI_PASSWORD = os.getenv('KIJIJI_PASSWORD')
UID = str(uuid.uuid1()).split('-')[0]

parentUrl = "https://www.kijiji.ca"

# define the capabilities
caps = DesiredCapabilities.CHROME
caps['goog:loggingPrefs'] = {'performance': 'ALL'}

# define Chrome options
options = webdriver.ChromeOptions()
options.add_argument("--disable-web-security")
options.add_argument("--allow-running-insecure-content")

driver = webdriver.Chrome(desired_capabilities=caps, chrome_options=options)

driver = login(driver, KIJIJI_EMAIL, KIJIJI_PASSWORD)
time.sleep(5)

resultsWanted = int(sys.argv[1])
print("Getting approximately {0} results for each query".format(resultsWanted))

queryText = sys.argv[2]

categorySearch = False
try:
	queryCategory = sys.argv[3]
	categorySearch = True
except:
	queryCategory = ""

for searchQuery in sys.argv[2:]:
	print("Starting search for {0}".format(searchQuery))

	driver = visitPage(driver, parentUrl)

	# time.sleep to be replaced by waitTillPageLoaded
	WebDriverWait(driver, 600).until(
		EC.presence_of_element_located((By.XPATH, '//*[@id="SearchKeyword"]'))
	)
	time.sleep(3)

	# put the query into the search box
	driver.execute_script("document.getElementById('SearchKeyword').value = '{0}'".format(searchQuery))

	# put the category into the category box (optional)
	if categorySearch:

		selectBox = driver.find_element_by_xpath("//select[@name='SearchCategory']")
		allCategories = selectBox.find_elements_by_tag_name("option")

		for category in allCategories:
			# print(category.get_attribute("value"))
			if category.text == queryCategory:
				category.click()

	# wait for the details to be entered by the user and pressing the search button
	element = WebDriverWait(driver, 600).until(
		EC.presence_of_element_located((By.CLASS_NAME, 'showing'))
	)
	print("Moved to search results page")

	pageIndex = 1
	adUrls = []

	# collect >= the specified number of ad URLs
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
			if adUrl is not None and adUrl.startswith('/'):
				adUrls.append(parentUrl + adUrl)

		allResults1 = driver.find_elements_by_css_selector('div.search-item')
		for result in allResults1:
			adUrl = result.get_attribute("data-vip-url")
			if adUrl is not None and adUrl.startswith('/'):
				adUrls.append(parentUrl + adUrl)

		# move to the next page
		pageIndex += 1
		newPageList = currentPageList[:-1] + ["page-" + str(pageIndex)] + currentPageList[-1:]
		newPage = '/'.join(newPageList)

		driver = visitPage(driver, newPage)

		urlCollectedCount = len(adUrls)
		print("Collected {0} URLs".format(urlCollectedCount))

		if urlCollectedCount >= resultsWanted:
			break

	print("Collected >= specified ad URLs")

	table = [["Business Name", "URL", "Phone Number", "Person Name", "Person Email", "Unique ID", "Msg Sending Status"]]
	adUrlCount = len(adUrls)
	print(adUrlCount)
	
	# for adIndex in range(len(adUrls)):
	for adIndex in range(resultsWanted):

		print("------------------------")

		payloadUrl = adUrls[adIndex]
		payloadUrl = payloadUrl.split("?")[0]
		print(payloadUrl)
		AD_ID = payloadUrl.split('/')[-1]
		if AD_ID.startswith("cas"):
			AD_ID = AD_ID.split("_")[-1]

		msgStatus = False
		uniqueID = str(uuid.uuid1()).split('-')[0]

		# retry the message sending process max 5 times
		for _pageLoadRetries in range(3):
			driver = visitPage(driver, payloadUrl)
			# wait till all the network requests have completed i.e. the page has completely been loaded
			try:
				WebDriverWait(driver, 600).until(
					EC.presence_of_element_located((By.XPATH, '//*[@id="vip-body"]'))
				)
			except:
				continue

			# recaptcha is loaded when the message box is clicked
			time.sleep(2)

			# make sure the ad is not resume type
			if isAdResumeType(driver):
				print("Skipping message sending to resume-uploading type ad")
				break

			if len(driver.find_elements_by_id('gpt-error-404')) > 0:
				print("Error 404 page")
				break

			externalSourceId = 'null'
			channelId = ''

			try:
				driver.find_element_by_id('message').click()
				htmlSourceCode = driver.page_source

				externalSourceId = re.findall(r'"externalSourceId":(.+?),', htmlSourceCode)[0]
				channelId = re.findall(r'"emailChannelId":(.+?)(,|})', htmlSourceCode)[0][0]
				print("external source id is " + externalSourceId)
				print("channel id is " + channelId)
			except Exception as e:
				pass
			time.sleep(3)

			msgStatus, driver = sendMessageDriver(driver, payloadUrl, ANTICAPTCHA_KEY, msgStatus, uniqueID, externalSourceId, channelId, KIJIJI_EMAIL)
			if msgStatus == True:
				break

		if msgStatus == False:
			print("Message sending failed / timeout!")

		allText = extractText(driver)

		# pick the business name from the ad
		businessName = getBusinessName(driver)
		allText += ("\n" + businessName)

		# pick the phone number from the ad
		phoneNumber = getPhoneNumber(allText)

		# pick the person name from the ad
		personName = getPersonName(driver)

		# pick up the email from the ad
		personEmail = getPersonEmail(allText)

		table.append([businessName, payloadUrl, phoneNumber, personName, personEmail, uniqueID, msgStatus])

		if (adUrlCount % 10 == 0):
			writeToFile(table)
			table = []

		if adIndex == (resultsWanted - 1):
			writeToFile(table)
			table = []

		adUrlCount -= 1
