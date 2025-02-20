
import hashlib
import requests
import json


class calix_client:
  def __init__(self,username, password, ip):
    self.username = username
    self.password = password
    self.ip = ip
    self.base_url = f'https://{ip}/'
    self.__login()
    self.__set_headers()

  def __login(self):
    nonce = self.__get_nonce()
    auth = self.__get_auth(nonce)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    data = {
      'Username': username,
      'auth': auth,
      'nonce': nonce
    }

    self.session = requests.Session()
    self.session.post(f'https://{ip}/login.cgi',headers=headers,data=data,verify=False)

  def __get_nonce(self):
    """get nonce token"""
    return requests.get(f'https://{self.ip}/get_nonce.cmd',verify=False).text
  
  def __get_auth(self, nonce):
    # Compute SHA-256 hash
    auth_string = f"{self.username}:{nonce}:{self.password}"
    auth_hash = hashlib.sha256(auth_string.encode()).hexdigest()
    return auth_hash

  def __set_headers(self):
    """sets headers for requests"""
    self.headers = {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-US,en',
      'Connection': 'keep-alive',
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      'Cookie': 'Authorization='+self.session.cookies['Authorization']
    }

  def __request(self, url, data):
    """shortens every get and set function"""
    resp = self.session.post(self.base_url+url, data=data, headers=self.headers, verify=False)
    
    if resp.status_code > 199 and resp.status_code < 300:
      return resp.text
    else: 
      return resp.status_code
    
  def get_session(self):
    return self.session

  def get_connection_status(self):
    """get connection status"""
    url = 'status_connection.cmd'
    data = {
      'action': 'getStatus'
    }
    return self.__request(url, data)

  def get_devices(self):
    """gets the dhcp table"""
    url = 'device_table.cmd'
    data = {
      'action': 'get'
    }
    return self.__request(url, data)

  def get_internet_status(self):
    """get internet status"""
    url = 'internet_status.cmd'
    data = {
      'action': 'getStatus'
    }

    return self.__request(url, data)

  def get_ethernet_status(self):
    """get ethernet status"""
    url = 'status_lanstatus_ipv6.cmd'
    data = {
      'action': 'getStatus'
    }
    return self.__request(url, data)
  
  def get_wireless_status(self):
    """get wireless status"""
    url = 'wlinfo.cmd'
    data = {
      'action': 'get_status'
    }
    return self.__request(url, data)

  def get_radio_settings(self):
    """get the current radio settings"""
    url = 'wlinfo.cmd'
    data = {
      'action': 'get_radio_setup'
    }
    return self.__request(url, data)
    
  def get_primary_network_ssid(self):
    url = 'wlinfo.cmd'
    data = {
      'action': 'get_ssid_setup',
      'wlSsidUsage': 'primary'
    }
    return self.__request(url, data)
  
  def get_guest_network_ssid(self):
    url = 'wlinfo.cmd'
    data = {
      'action': 'get_pool_status',
      'wlSsidUsage': 'guest'
    }
    return self.__request(url, data)
  
  def get_wps_settings(self):
    """get wps settings"""
    url = 'wps.cmd'
    data = {
      'action': 'get_status'
    }
    return self.__request(url, json.dumps(data))

