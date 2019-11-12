#!/usr/bin/env python3
import hmac
import time
import argparse
import requests
import json

class SurfboardHNAP:

    def __init__(self):
        self.s = requests.Session()
        self.privatekey = None
        self.cookie_id = None
        self.host = None

    def generate_keys(self, challenge, pubkey, password):
        privatekey = hmac.new(pubkey+password, challenge).hexdigest().upper()
        passkey = hmac.new(privatekey.encode(), challenge).hexdigest().upper()
        self.privatekey = privatekey
        return (privatekey, passkey)

    def generate_hnap_auth(self, operation):
        privkey = self.privatekey
        curtime = str(int(time.time() * 1000))
        auth_key = curtime + '"http://purenetworks.com/HNAP1/{}"'.format(operation)
        privkey = privkey.encode()
        auth = hmac.new(privkey, auth_key.encode())
        return auth.hexdigest().upper() + ' ' + curtime

    def _login_request(self, host):
        url = 'http://{}/HNAP1/'.format(host)
        headers = {#'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.34 Safari/537.36',
                #'Content-Type' : 'application/json; charset=UTF-8',
                #'Accept' : 'application/json, text/javascript, */*; q=0.01',
                #'X-Requested-With' : 'XMLHttpRequest',
                'SOAPAction' : '"http://purenetworks.com/HNAP1/Login"'}
        payload = '{"Login":{"Action":"request","Username":"admin","LoginPassword":"","Captcha":"","PrivateLogin":"LoginPassword"}}'

        r = self.s.post(url, headers=headers, data=payload, stream=True)
        return r

    def _login_real(self, host, cookie_id, privatekey, passkey):
        url = 'http://{}/HNAP1/'.format(host)
        auth = self.generate_hnap_auth('Login')
        headers = {'HNAP_AUTH' : auth,
                #'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.34 Safari/537.36',
                #'Content-Type' : 'application/json; charset=UTF-8',
                #'Accept' : 'application/json, text/javascript, */*; q=0.01',
                #'X-Requested-With' : 'XMLHttpRequest',
                'SOAPAction' : '"http://purenetworks.com/HNAP1/Login"'}
        cookies = {'uid' : '{}'.format(cookie_id),
                'PrivateKey' : '{}'.format(privatekey)}
        payload = {'Login': {'Action': 'login',
                'Captcha': '',
                'LoginPassword': '{}'.format(passkey),
                'PrivateLogin': 'LoginPassword',
                'Username': 'admin'}}

        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        return r

    def login(self, host, password):
        self.host = host
        r = self._login_request(host)
        lrdata = json.loads(r.text)['LoginResponse']
        cookie_id = lrdata['Cookie']
        pubkey = lrdata['PublicKey']
        challenge = lrdata['Challenge']

        self.cookie_id = cookie_id

        privkey, passkey = self.generate_keys(challenge.encode(), 
                                              pubkey.encode(), 
                                              password.encode())
        return self._login_real(host, cookie_id, privkey, passkey)

    def get_status(self):
        host = self.host
        cookie_id = self.cookie_id 
        privatekey = self.privatekey

        url = 'http://{}/HNAP1/'.format(host)
        auth = self.generate_hnap_auth('GetMultipleHNAPs')
        headers = {'HNAP_AUTH' : auth,
                #'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.34 Safari/537.36',
                #'Content-Type' : 'application/json; charset=UTF-8',
                #'Accept' : 'application/json, text/javascript, */*; q=0.01',
                'SOAPACTION' : '"http://purenetworks.com/HNAP1/GetMultipleHNAPs"',
                #'Referer' : 'http://{}/MotoSecurity.html'.format(host)
                }

        '''payload = {'GetMultipleHNAPs': {'GetMotoStatusStartupSequence': '',
                'GetMotoStatusConnectionInfo': '',
                'GetMotoStatusDownstreamChannelInfo': '',
                'GetMotoStatusUpstreamChannelInfo': '',
                'GetMotoLagStatus': ''}}'''

        cookies = {'uid' : '{}'.format(cookie_id),
                'PrivateKey' : '{}'.format(privatekey)}
        payload = {'GetMultipleHNAPs': {'GetMotoStatusSoftware': '',
                'GetMotoStatusXXX': ''}}

        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        return r

    def get_security(self):
        host = self.host
        cookie_id = self.cookie_id
        privatekey = self.privatekey

        url = 'http://{}/HNAP1/'.format(host)
        auth = self.generate_hnap_auth('GetMultipleHNAPs')
        headers = {'HNAP_AUTH' : auth,
                #'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.34 Safari/537.36',
                #'Content-Type' : 'application/json',
                #'Accept' : 'application/json',
                'SOAPACTION' : '"http://purenetworks.com/HNAP1/GetMultipleHNAPs"',
                #'Referer' : 'http://{}/MotoSecurity.html'.format(host),
                #'Origin' : 'http://{}'.format(host),
                #'Cookie' : 'uid={}; PrivateKey={}'.format(cookie_id, privatekey),
                #'Accept-Encoding' : 'gzip, deflate',
                #'Accept-Language' : 'en-US,en-XA;q=0.9,en;q=0.8'
                }

        cookies = {'uid' : '{}'.format(cookie_id),
                'PrivateKey' : '{}'.format(privatekey)}
        payload = {'GetMultipleHNAPs': {'GetMotoStatusSecAccount': '',
                'GetMotoStatusSecXXX': ''}}

        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        return r

    def reboot(self):
        host = self.host
        cookie_id = self.cookie_id
        privatekey = self.privatekey

        url = 'http://{}/HNAP1/'.format(host)
        auth = self.generate_hnap_auth('SetStatusSecuritySettings')
        headers = {'HNAP_AUTH' : auth,
                #'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.34 Safari/537.36',
                #'Content-Type' : 'application/json; charset=UTF-8',
                #'Accept' : 'application/json, text/javascript, */*; q=0.01',
                #'X-Requested-With' : 'XMLHttpRequest',
                'SOAPAction' : '"http://purenetworks.com/HNAP1/SetStatusSecuritySettings"'}

        cookies = {'uid' : '{}'.format(cookie_id),
                'PrivateKey' : '{}'.format(privatekey)}
        payload = {'SetStatusSecuritySettings': {'MotoStatusSecurityAction': '1',
                'MotoStatusSecXXX': 'XXX'}}
        r = self.s.post(url, headers=headers, cookies=cookies, json=payload)
        return r


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='192.168.100.1', 
            help='Hostname or IP of your modem (Default: 192.168.100.1)')
    parser.add_argument('--password', default='motorola', 
            help='Admin password (Default: motorola)')
    parser.add_argument('--dryrun', '-d', action='store_true', 
                        help="Logs in but doesn't reboot")
    return parser.parse_args()

if __name__ == '__main__':
    args = get_arguments()
    host = args.host
    password = args.password

    h = SurfboardHNAP()
    r = h.login(host, password)
    print('login: {}'.format(r))
    r = h.get_status()
    print('status: {}'.format(r))
    if not args.dryrun:
        r = h.reboot()
        print('reboot: {}'.format(r))
        print(r.text)
    r = h.get_security()
    print('get_security: {}'.format(r))
