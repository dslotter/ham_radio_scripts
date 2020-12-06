#!/usr/bin/python3

# importing the requests library
import argparse
import os
import requests
import xmltodict

# Version of QRZ.com XML interface
qrz_interface_version = "1.33"

# Username and Password for QRZ Website are provided in environment variables
username = os.environ.get('QRZ_USERNAME')
password = os.environ.get('QRZ_PASSWORD')

# Request format is:
# http://xmldata.qrz.com/xml/API_VERSION/?username=xx1xxx;password=abcdef

# QRZ.com XML api-endpoint
QRZ_URL = "http://xmldata.qrz.com/xml/" + qrz_interface_version + "/"
QRZ_URL_SECURE = "https://xmldata.qrz.com/xml/" + qrz_interface_version + "/"
 
def getQRZSessionKey(): 
	Key = "Invalid"

	# defining a params dict for the parameters to be sent to the API
	PARAMS = {'username':username, 'password':password}
 
	print ("Authenticating to QRZ.com...")

	# sending get request and saving the response as response object
	r = requests.get(url = QRZ_URL_SECURE, params = PARAMS)

	if r.status_code == 200:
		print ("200 OK\n") 

		# Parse XML directly into Dict
		raw_session = xmltodict.parse(r.content)
 
		# Retrieve Session Key
		Key = raw_session['QRZDatabase']['Session']['Key']
	else:
		print ("HTTP Status = {0}".format(r.status_code))

	return Key

def getCallsignInfo(sessionKey, callsign):
	raw_session = None

	# defining a params dict for the parameters to be sent to the API
	PARAMS = {'username':username, 'password':password, 'callsign':callsign}

	print ("Requesting callsign information...")

	# sending get request and saving the response as response object
	r = requests.get(url = QRZ_URL, params = PARAMS)

	if r.status_code == 200:
		print ("200 OK\n")

		# Parse XML directly into Dict
		raw_session = xmltodict.parse(r.content)
	else:
		print ("HTTP Status = {0}".format(r.status_code))

	return raw_session
 
def displayCallSignInfo(callSignXml):
	callsign=""
	aliases=""
	fname=""
	lastname=""
	addr1=""
	city=""
	state=""
	zip=""
	country=""
	county=""
	latitude=""
	longitude=""
	grid=""
	dxcc=""
	land=""
	email=""
	efdate=""
	expdate=""
	lclass=""

	try:
		callsign  = callSignXml['QRZDatabase']['Callsign']['call']
	except KeyError as error:
		print

	try:
		aliases   = callSignXml['QRZDatabase']['Callsign']['aliases']
	except KeyError as error:
		print

	try:
		fname     = callSignXml['QRZDatabase']['Callsign']['fname']
	except KeyError as error:
		print

	try:
		lastname  = callSignXml['QRZDatabase']['Callsign']['name']
	except KeyError as error:
		print

	try:
		addr1     = callSignXml['QRZDatabase']['Callsign']['addr1']
	except KeyError as error:
		print

	try:
		city      = callSignXml['QRZDatabase']['Callsign']['addr2']
	except KeyError as error:
		print

	try:
		state     = callSignXml['QRZDatabase']['Callsign']['state']
	except KeyError as error:
		print

	try:
		zip       = callSignXml['QRZDatabase']['Callsign']['zip']
	except KeyError as error:
		print

	try:
		country   = callSignXml['QRZDatabase']['Callsign']['country']
	except KeyError as error:
		print

	try:
		county    = callSignXml['QRZDatabase']['Callsign']['county']
	except KeyError as error:
		print

	try:
		latitude  = callSignXml['QRZDatabase']['Callsign']['lat']
	except KeyError as error:
		print

	try:
		longitude = callSignXml['QRZDatabase']['Callsign']['lon']
	except KeyError as error:
		print

	try:
		email     = callSignXml['QRZDatabase']['Callsign']['email']
	except KeyError as error:
		print

	try:
		grid      = callSignXml['QRZDatabase']['Callsign']['grid']
	except KeyError as error:
		print

	try:
		dxcc      = callSignXml['QRZDatabase']['Callsign']['dxcc']
	except KeyError as error:
		print

	try:
		land      = callSignXml['QRZDatabase']['Callsign']['land']
	except KeyError as error:
		print

	try:
		efdate    = callSignXml['QRZDatabase']['Callsign']['efdate']
	except KeyError as error:
		print

	try:
		expdate   = callSignXml['QRZDatabase']['Callsign']['expdate']
	except KeyError as error:
		print

	try:
		lclass    = callSignXml['QRZDatabase']['Callsign']['class']
	except KeyError as error:
		print

	print ("Callsign: " + callsign)
	print ("Aliases: " + aliases)
	print ("Name: " + fname + ' ' + lastname)
	print ("Address: " + addr1)
	print ("City, State, Zip: " + city + ', ' + state + ', ' + zip)
	print ("Country: " + country)
	print ("County: " + county)
	print ("Latitude: " + latitude)
	print ("Longitude: " + longitude)
	print ("Grid square: " + grid)
	print ("DXCC entity ID (country code): " + dxcc)
	print ("DXCC country name: " + land)
	print ("Email: " + email)
	print ("License effective date: " + efdate)
	print ("License expiration date: " + expdate)
	print ("License class: " + lclass)

	return

def main(): 
	if not username or not password:
		raise Exception("Username or Password missing.")

	# Parse callsign from command line
	parser = argparse.ArgumentParser()
	parser.add_argument("callsign")
	args = parser.parse_args()
	callsign = args.callsign
	if callsign is "":
		return

	# Retrieve Session Key
	sessionKey = getQRZSessionKey()

	# Retrieve and display call sign information
	if sessionKey is not "Invalid":
		callSignXml = getCallsignInfo(sessionKey, callsign)
		if callSignXml is not None:
			displayCallSignInfo(callSignXml)
		else:
			print ("Failed to retrieve callsign info from QRZ.com.")
	else:
		print ("Failed to authenticate to QRZ.com.")

	return

if __name__ == "__main__": 
  
    # calling main function 
    main()
