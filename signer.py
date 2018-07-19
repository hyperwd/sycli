#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time         : 2018/7/9 15:45
# @Author       : Hyperwd
# @contact      : 435904632@qq.com  
# @File         : sign.py
# @description  : 华为云基于AK,SK的认证


# This version makes a GET request and passes the signature in the Authorization header.

import datetime
import hashlib
import hmac
import requests
from urllib.parse import quote


class SignError(Exception):
    pass


class Sign(object):

    def __init__(self, access_key, secret_key, project_id, req_method, req_host, req_uri, x_project_id='',
                 req_query_param={},
                 req_custom_headers={}, req_body='', req_timeout=10):

        """
        :param access_key: ak
        :param secret_key: sk
        :param project_id: 与host对应的单个region父项目ID,也是租户ID
        :param x_project_id: 单个子项目id
        :param req_method: GET,POST,PUT等
        :param req_host: 请求url,例如 ecs.cn-north-1.myhuaweicloud.com
        :param req_uri:  请求资源路径,例如/v2/tenant_id/servers/
        :param req_query_param: 请求查询参数,例如 { 'name':'xxx','status':'ACTIVE' }或为空
        :param req_custom_headers: 自定义请求头信息，可任意增加
        :param req_body: 请求消息体
        :param req_timeout: 设置请求超时时间，默认10秒
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.project_id = project_id
        self.x_project_id = x_project_id
        self.req_method = req_method
        self.req_host = req_host
        self.req_uri = req_uri
        self.req_query_param = req_query_param
        self.req_custom_headers = req_custom_headers
        self.req_body = req_body
        self.req_timeout = req_timeout

    # Key derivation functions. See:
    @staticmethod
    def get_signature_key(sk, date_stamp, region_name, service_name):

        key = ('SDK' + sk).encode('utf-8')
        for d in [date_stamp, region_name, service_name, 'sdk_request']:
            key = hmac.new(key=key, msg=d.encode('utf-8'), digestmod=hashlib.sha256).digest()
        return key

    @staticmethod
    def query_string(idict):

        que_list = []
        for key, value in idict.items():
            if value == '':
                kv = quote(key)
            else:
                kv = quote(key) + '=' + quote(value)
            que_list.append(kv)
        que_list.sort()
        return '&'.join(que_list)

    def sign(self):

        self.req_date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        self.req_datestamp = datetime.datetime.utcnow().strftime('%Y%m%d')  # Date w/o time, used in credential scope
        self.algorithm = 'SDK-HMAC-SHA256'
        self.req_region = self.req_host.split('.')[0]
        self.req_service = self.req_host.split('.')[1]

        # ************* TASK 1: CREATE A CANONICAL REQUEST *************
        # Step 1 is to define the verb (GET, POST, etc.)--alredy done--slef.req_method.
        # Step 2: Create canonical URI--the part of the URI from domain to query---already done--self.req_uri
        # Step 3: Create the canonical query string.--use func query_string above

        self.canonical_querystring = self.query_string(self.req_query_param)

        # Step 4: Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.

        self.canonical_headers = 'host:' + self.req_host.lower() + '\n' + 'x-sdk-date:' + self.req_date + '\n'

        # Step 5: Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers lists those that you want to be included in the
        # hash of the request. "host" and "x-amz-date" are always required.

        self.signed_headers = 'host;x-sdk-date'

        # Step 6: Create payload hash (hash of the request body content)

        self.payload_hash = hashlib.sha256(self.req_body.encode('utf-8')).hexdigest()

        # Step 7: Combine elements to create canonical request
        if self.req_uri.endswith('/'):
            self.req_uri = self.req_uri
        else:
            self.req_uri = self.req_uri + '/'

        self.canonical_request = self.req_method.upper() + '\n' + self.req_uri + '\n' + self.canonical_querystring + '\n' + self.canonical_headers + '\n' + self.signed_headers + '\n' + self.payload_hash

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use,SHA-256 (recommended)
        self.credential_scope = self.req_datestamp + '/' + self.req_region + '/' + self.req_service + '/' + 'sdk_request'
        self.string_to_sign = self.algorithm + '\n' + self.req_date + '\n' + self.credential_scope + '\n' + hashlib.sha256(
            self.canonical_request.encode('utf-8')).hexdigest()

        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        self.signing_key = self.get_signature_key(self.secret_key, self.req_datestamp, self.req_region,
                                                  self.req_service)

        # Sign the string_to_sign using the signing_key
        self.signature = hmac.new(self.signing_key, (self.string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        self.authorization_header = self.algorithm + ' ' + 'Credential=' + self.access_key + '/' + self.credential_scope + ', ' + 'SignedHeaders=' + self.signed_headers + ', ' + 'Signature=' + self.signature

        # The request can include any headers, but MUST include "host", "x-sdk-date",
        # and (for this scenario) "Authorization". "host" and "x-sdk-date" must
        # be included in the canonical_headers and signed_headers, as noted
        # earlier. Order here is not significant.
        # Python note: The 'host' header is added automatically by the Python 'requests' library.
        if self.x_project_id:
            self.headers_base = {'X-Project-Id': self.x_project_id, 'x-sdk-date': self.req_date,
                             'Authorization': self.authorization_header}
        else:
            self.headers_base = { 'x-sdk-date': self.req_date,
                                 'Authorization': self.authorization_header}

        self.headers = {**self.headers_base, **self.req_custom_headers}

        # ************* SEND THE REQUEST *************
        if self.req_query_param:
            self.request_url = 'https://' + self.req_host + self.req_uri[:-1] + '?' + self.canonical_querystring
        else:
            self.request_url = 'https://' + self.req_host + self.req_uri[:-1]

        try:

            if self.req_method == 'GET':
                self.r = requests.get(self.request_url, data=self.req_body, headers=self.headers,
                                      timeout=self.req_timeout)
            elif self.req_method == 'POST':
                self.r = requests.post(self.request_url, data=self.req_body, headers=self.headers,
                                       timeout=self.req_timeout)
            elif self.req_method == 'PUT':
                self.r = requests.put(self.request_url, data=self.req_body, headers=self.headers,
                                      timeout=self.req_timeout)
            elif self.req_method == 'DELETE':
                self.r = requests.delete(self.request_url, data=self.req_body, headers=self.headers,
                                         timeout=self.req_timeout)
            elif self.req_method == 'PATCH':
                self.r = requests.patch(self.request_url, data=self.req_body, headers=self.headers,
                                        timeout=self.req_timeout)
            else:
                raise SignError('request method need one of GET,POST,PUT,DELETE,PATCH')
            print(self.headers)
            print(self.request_url)
            print(self.r.headers)
            return self.r.status_code, self.r.json()

        except Exception as e:
            return e
