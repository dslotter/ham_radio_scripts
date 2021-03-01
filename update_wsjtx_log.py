#!/usr/bin/python3
"""
Python script to update WSJT-X logfiles with missing grid squares and names

Written by Dave Slotter, <w3djs@arrl.net>

Amateur Radio Callsign W3DJS

Created  February 21, 2021 - Copyrighted under the GPL v3
Modified February 28, 2021 - Enhanced session and error handling (1.0.1)
Modified February 28, 2021 - Added support for callook.info (1.1)
"""

import argparse
import os
import sys
import time
import requests
import xmltodict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WSJTX_LOG_PATH = "/home/pi/.local/share/WSJT-X/wsjtx_log.adi"

# Version of QRZ.com XML interface
QRZ_INTERFACE_VERSION = "1.34"

# Request format is:
# http://xmldata.qrz.com/xml/API_VERSION/?username=xx1xxx;password=abcdef

# QRZ.com XML api-endpoint
QRZ_URL = "http://xmldata.qrz.com/xml/" + QRZ_INTERFACE_VERSION + "/"
QRZ_URL_SECURE = "https://xmldata.qrz.com/xml/" + QRZ_INTERFACE_VERSION + "/"

# Callook.info api-endpoint
CALLOOK_URL = "https://callook.info/"

# Blech: globals
APPEND_LOG_FLAG = False
NEW_LOG = ""
NEW_LOG_OFFSET = 0
OLD_LOG_SIZE = 0


def exit_auth_error():
    """ Exit due to failed authentication """
    print("Can not obtain session key for callsign lookup provider")
    print("Make sure you have a paid XML API subscription for QRZ.")
    sys.exit(7)  # RPC_AUTHERROR


class UpdateWsjtxLog:
    """ Class UpdateWsjtxLog """
    # pylint: disable=too-many-instance-attributes
    # These are all required variables.
    username = ""
    password = ""
    session_key = ""
    wsjtx_logfile = None
    wsjtx_size = 0
    config = ""
    operator = ""
    name_s = ""
    name_r = ""
    call = ""
    date = ""
    time_on = ""
    date_off = ""
    time_off = ""
    band = ""
    mode = ""
    submode = ""
    frequency = ""
    power = ""
    rst_r = ""
    rst_s = ""
    grid_r = ""
    grid_s = ""
    comment = ""
    adif_log_entry = ""

    def __init__(self, data_source):
        self.reset_vals()
        self.station_callsign = ""
        self.wsjtx_size = 0
        self.data_source = data_source

    def reset_vals(self):
        """ Reset all values to beginning state """
        self.name_r = ""
        self.call = ""
        self.station_callsign = ""
        self.operator = ""
        self.date = ""
        self.time_on = ""
        self.time_off = ""
        self.band = ""
        self.mode = ""
        self.submode = ""
        self.frequency = ""
        self.power = ""
        self.rst_r = ""
        self.rst_s = ""
        self.grid_r = ""
        self.grid_s = ""
        self.comment = ""

    def parse_adif(self):
        """ Parse ADIF record """
        # pylint: disable=too-many-branches
        # pylint: disable=too-many-statements
        # It's a parser after all
        print("\nParsing log entry from WSJT-X...\n")
        for token in [
                'call', 'gridsquare', 'mode', 'submode', 'rst_sent',
                'rst_rcvd', 'qso_date', 'time_on', 'qso_date_off', 'time_off',
                'band', 'freq', 'station_callsign', 'my_gridsquare', 'tx_pwr',
                'comment', 'name', 'operator'
        ]:
            strbuf = str(self.adif_log_entry)
            search_token = "<" + token + ":"
            start = strbuf.lower().find(search_token)
            if start == -1:
                continue
            end = strbuf.find(':', start) - 1
            if end == -1:
                break
            pos = end + 2
            found_num = True
            while found_num is True:
                if strbuf[pos + 1].isdigit() is True:
                    pos = pos + 1
                else:
                    found_num = False

            attr_len = int(strbuf[end + 2:pos + 1])
            strbuf = str(self.adif_log_entry)
            attr = strbuf[pos + 2:pos + 2 + int(attr_len)]
            # Enable for debugging only:
            # print("%s: %s" % (token, attr))
            if not attr:
                continue

            if token == 'call':
                self.call = attr
            elif token == 'gridsquare':
                self.grid_r = attr[0:4]
            elif token == 'mode':
                self.mode = attr
            elif token == 'submode':
                self.submode = attr
            elif token == 'rst_sent':
                self.rst_s = attr
            elif token == 'rst_rcvd':
                self.rst_r = attr
            elif token == 'qso_date':
                self.date = attr
            elif token == 'time_on':
                self.time_on = attr
            elif token == 'qso_date_off':
                self.date_off = attr
            elif token == 'time_off':
                self.time_off = attr
            elif token == 'band':
                self.band = attr
            elif token == 'freq':
                self.frequency = attr
            elif token == 'station_callsign':
                self.station_callsign = attr
            elif token == 'my_gridsquare':
                self.grid_s = attr
            elif token == 'tx_pwr':
                self.power = attr
            elif token == 'comment':
                self.comment = attr
            elif token == 'name':
                self.name_r = attr
            elif token == 'operator':
                self.operator = attr

    def update_log_entry(self):
        """ Log updated QSO """
        if self.submode == "":
            new_adif_log_entry = """<call:%d>%s <gridsquare:%d>%s \
<mode:%d>%s \
<rst_sent:%d>%s \
<rst_rcvd:%d>%s \
<qso_date:%d>%s \
<time_on:%d>%s \
<qso_date_off:%d>%s \
<time_off:%d>%s \
<band:%d>%s \
<freq:%d>%s \
<station_callsign:%d>%s \
<my_gridsquare:%d>%s \
<tx_pwr:%d>%s \
<comment:%d>%s \
<name:%d>%s \
<operator:%d>%s \
<app_uwl_source:%d>%s \
<eor>\n""" % \
             (len(self.call), self.call,
              len(self.grid_r), self.grid_r,
              len(self.mode), self.mode,
              len(self.rst_s), self.rst_s,
              len(self.rst_r), self.rst_r,
              len(self.date), self.date,
              len(self.time_on), self.time_on,
              len(self.date_off), self.date_off,
              len(self.time_off), self.time_off,
              len(self.band), self.band,
              len(self.frequency), self.frequency,
              len(self.station_callsign), self.station_callsign,
              len(self.grid_s), self.grid_s,
              len(self.power), self.power,
              len(self.comment), self.comment,
              len(self.name_r), self.name_r,
              len(self.operator), self.operator,
              len(self.data_source), self.data_source)
        else:
            new_adif_log_entry = """<call:%d>%s " \
<gridsquare:%d>%s \
<mode:%d>%s \
<submode:%d>%s \
<rst_sent:%d>%s \
<rst_rcvd:%d>%s \
<qso_date:%d>%s \
<time_on:%d>%s \
<qso_date_off:%d>%s \
<time_off:%d>%s \
<band:%d>%s \
<freq:%d>%s \
<station_callsign:%d>%s \
<my_gridsquare:%d>%s \
<tx_pwr:%d>%s \
<comment:%d>%s \
<name:%d>%s \
<operator:%d>%s \
<app_uwl_source:%d>%s \
<eor>\n""" % \
             (len(self.call), self.call,
              len(self.grid_r), self.grid_r,
              len(self.mode), self.mode,
              len(self.submode), self.submode,
              len(self.rst_s), self.rst_s,
              len(self.rst_r), self.rst_r,
              len(self.date), self.date,
              len(self.time_on), self.time_on,
              len(self.date_off), self.date_off,
              len(self.time_off), self.time_off,
              len(self.band), self.band,
              len(self.frequency), self.frequency,
              len(self.station_callsign), self.station_callsign,
              len(self.grid_s), self.grid_s,
              len(self.power), self.power,
              len(self.comment), self.comment,
              len(self.name_r), self.name_r,
              len(self.operator), self.operator,
              len(self.data_source), self.data_source)

        # Deferred write to prevent unwanted recursion
        # pylint: disable=global-statement
        global APPEND_LOG_FLAG
        global NEW_LOG
        global NEW_LOG_OFFSET
        APPEND_LOG_FLAG = True
        NEW_LOG = new_adif_log_entry
        global OLD_LOG_SIZE
        NEW_LOG_OFFSET = OLD_LOG_SIZE

    def get_callook_session_key(self):
        """ There is no Session Key for Callook.info """
        self.session_key = "VALID"
        return "VALID"

    def get_qrz_session_key(self):
        """ Get QRZ Session Key """
        key = "INVALID"

        # defining a params dict for the parameters to be sent to the API
        params = {'username': self.username, 'password': self.password,
                  'agent': 'update_wsjtx_log_1.1'}

        print("Authenticating to QRZ.com...")

        # sending get request and saving the response as response object
        request = requests.get(url=QRZ_URL_SECURE, params=params)

        if request.status_code == 200:
            print("200 OK\n")

            # Parse XML directly into Dict
            raw_session = xmltodict.parse(request.content)

            # Enable for debugging only:
            # print("get_qrz_session_key raw sesssion:\n", raw_session, "\n")

            # Check for error returned
            if 'Error' in raw_session['QRZDatabase']['Session']:
                error = raw_session['QRZDatabase']['Session']['Error']
                if error == 'Username/password incorrect':
                    return key

            # Check for non-subscriber
            if 'SubExp' in raw_session['QRZDatabase']['Session']:
                subexp = raw_session['QRZDatabase']['Session']['SubExp']
                if subexp == 'non-subscriber':
                    return key

            # Retrieve Session Key
            key = raw_session['QRZDatabase']['Session']['Key']
        else:
            print("HTTP Status = {0}".format(request.status_code))

        # Enable for debugging:
        # print("Session key:", key)
        return key

    def get_session_key(self):
        """ Get session key for online callsign lookup provider """
        key = "INVALID"
        if self.data_source == "qrz.com":
            key = self.get_qrz_session_key()
        elif self.data_source == "callook.info":
            key = self.get_callook_session_key()
        # Enable for debugging:
        # print("get_session_key:", self.session_key)
        return key

    def get_callook_callsign_info(self):
        """ Request callsign info from QRZ """
        raw_session = None

        # creating the URL to use for the request
        request_url = CALLOOK_URL + self.call + "/xml"

        print("Requesting callsign information for {}...".format(self.call))

        # sending get request and saving the response as response object
        request = requests.get(url=request_url)

        if request.status_code == 200:
            print("200 OK\n")

            # Parse XML directly into Dict
            raw_session = xmltodict.parse(request.content)
        else:
            print("HTTP Status = {0}".format(request.status_code))

        # Enable for debugging only:
        # print("get_callook_callsign_info raw sesssion:\n", raw_session, "\n")

        return raw_session

    def get_qrz_callsign_info(self):
        """ Request callsign info from QRZ """
        raw_session = None

        # defining a params dict for the parameters to be sent to the API
        params = {'s': self.session_key, 'callsign': self.call}

        print("Requesting callsign information for {}...".format(self.call))

        # sending get request and saving the response as response object
        request = requests.get(url=QRZ_URL, params=params)

        if request.status_code == 200:
            print("200 OK\n")

            # Parse XML directly into Dict
            raw_session = xmltodict.parse(request.content)
        else:
            print("HTTP Status = {0}".format(request.status_code))

        # Enable for debugging only:
        # print("get_qrz_callsign_info raw sesssion:\n", raw_session, "\n")

        # Check for Session Timeout
        if 'Error' in raw_session['QRZDatabase']['Session']:
            error = raw_session['QRZDatabase']['Session']['Error']
            if error == 'Session Timeout':
                print("Session Timeout: obtaining new session key")
                self.session_key = self.get_session_key()
                if self.session_key == "INVALID":
                    exit_auth_error()

        # Check for error returned
        if 'Error' in raw_session['QRZDatabase']['Session']:
            error = raw_session['QRZDatabase']['Session']['Error']
            print("Error when querying QRZ.COM: ", error)

        return raw_session

    def get_callsign_info(self):
        """ Request callsign info from online callsign lookup provider """
        if self.data_source == "qrz.com":
            callsign_info = self.get_qrz_callsign_info()
        elif self.data_source == "callook.info":
            callsign_info = self.get_callook_callsign_info()
        return callsign_info

    def parse_callook_callsign_info(self, call_sign_xml):
        """ Parse name and grid from Callook """
        try:
            status = call_sign_xml['callook']['status']
            if status in ('INVALID', 'UPDATING'):
                print("Call lookup failed:", status)
                return
        except KeyError as error:
            print("Error =", error)

        try:
            if self.name_r == "":
                self.name_r = \
                    call_sign_xml['callook']['name']
                print("Missing name: " + self.name_r)
        except KeyError as error:
            print("Error =", error)

        try:
            if self.grid_r == "":
                self.grid_r = \
                    call_sign_xml['callook']['location']['gridsquare'][0:4]
                print("Missing Grid square: " + self.grid_r)
        except KeyError as error:
            print("Error =", error)

    def parse_qrz_callsign_info(self, call_sign_xml):
        """ Parse name and grid from QRZ """
        try:
            if self.name_r == "":
                self.name_r = \
                    call_sign_xml['QRZDatabase']['Callsign']['name_fmt']
                print("Missing name: " + self.name_r)
        except KeyError as error:
            print("Error =", error)

        try:
            if self.grid_r == "":
                self.grid_r = \
                    call_sign_xml['QRZDatabase']['Callsign']['grid'][0:4]
                print("Missing Grid square: " + self.grid_r)
        except KeyError as error:
            print("Error =", error)

    def parse_callsign_info(self, call_sign_xml):
        """ Parse name and grid from online callsign lookup provider """
        if self.data_source == "qrz.com":
            self.parse_qrz_callsign_info(call_sign_xml)
        elif self.data_source == "callook.info":
            self.parse_callook_callsign_info(call_sign_xml)


class FsEventHandler(FileSystemEventHandler):
    """ Class FsEventHandler """
    update_wsjtx_log = None

    def __init__(self, data_source):
        self.update_wsjtx_log = UpdateWsjtxLog(data_source)

        # Username and Password for QRZ Website are provided in
        # environment variables
        self.update_wsjtx_log.username = os.environ.get('QRZ_USERNAME')
        self.update_wsjtx_log.password = os.environ.get('QRZ_PASSWORD')
        if not self.update_wsjtx_log.username or \
           not self.update_wsjtx_log.password:
            raise Exception("QRZ Username or Password missing.")

        # Retrieve Session Key
        self.update_wsjtx_log.session_key = \
            self.update_wsjtx_log.get_session_key()
        if self.update_wsjtx_log.session_key == "INVALID":
            print("Got here 2")
            exit_auth_error()

    def on_modified(self, event):
        """ Called when WSJT-X logfile is modified """
        if APPEND_LOG_FLAG:
            # This is a "red herring" so skip
            return

        if (event.event_type == 'modified') and \
           (event.src_path == WSJTX_LOG_PATH):
            print("Modified WSJT-X logfile.")
            self.update_wsjtx_log.wsjtx_size = \
                os.path.getsize(WSJTX_LOG_PATH)
            print("WSJT-X logfile new size: ",
                  self.update_wsjtx_log.wsjtx_size)
            self.update_wsjtx_log.wsjtx_logfile = \
                open(WSJTX_LOG_PATH, "r+")
            self.update_wsjtx_log.wsjtx_logfile.seek(OLD_LOG_SIZE)
            line = self.update_wsjtx_log.wsjtx_logfile.readline()
            print("Read new log entry:\n\n", line)
            self.update_wsjtx_log.adif_log_entry = line
            self.update_wsjtx_log.parse_adif()
            call_sign_xml = self.update_wsjtx_log.get_callsign_info()
            if call_sign_xml is not None:
                self.update_wsjtx_log.parse_callsign_info(call_sign_xml)
                self.update_wsjtx_log.update_log_entry()
                self.update_wsjtx_log.reset_vals()
            else:
                print("Failed to retrieve callsign info from QRZ.com.")
            self.update_wsjtx_log.wsjtx_logfile.close()


def main():
    """ Main function """
    # pylint: disable=global-statement
    global APPEND_LOG_FLAG
    global NEW_LOG
    global NEW_LOG_OFFSET

    print("*****************************************************")
    print("* WSJT-X Log Updater written by Dave Slotter, W3DJS *")
    print("*****************************************************\n")

    # Parse command line argument for data source
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", help="Specify data source: QRZ or CALLOOK")
    args = parser.parse_args()
    data_source = args.source.upper()
    if data_source == 'QRZ':
        data_source = "qrz.com"
        print("Using data source: QRZ.com")
    elif data_source == 'CALLOOK':
        data_source = "callook.info"
        print("Using data source: callook.info")

    # Process log entries - Watch for changes to WSJTX ADIF log.
    event_handler = FsEventHandler(data_source)

    # pylint: disable=too-many-nested-blocks
    while True:
        while not APPEND_LOG_FLAG:
            global OLD_LOG_SIZE
            OLD_LOG_SIZE = os.path.getsize(WSJTX_LOG_PATH)
            print("WSJT-X logfile current size:", OLD_LOG_SIZE)

            observer = Observer()
            observer.schedule(event_handler, WSJTX_LOG_PATH, recursive=False)
            observer.start()
            print("Waiting for additions to WSJT-X logfile...")
            try:
                while True:
                    time.sleep(1)
                    if APPEND_LOG_FLAG:
                        APPEND_LOG_FLAG = False
                        print("Writing Log entry:\n\n", NEW_LOG)
                        wsjtx_logfile = open(WSJTX_LOG_PATH, "r+")
                        wsjtx_logfile.seek(NEW_LOG_OFFSET)
                        wsjtx_logfile.write(NEW_LOG)
                        wsjtx_logfile.close()
                        break

            # pylint: disable=broad-except
            except Exception as exception:
                print("Exception: ", exception)

            finally:
                observer.stop()
                observer.join()
            APPEND_LOG_FLAG = False


if __name__ == "__main__":

    # calling main function
    main()
