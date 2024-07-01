#!/usr/bin/env python2.5
#
# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
## """Helper classes which help converting a url to a list of SB expressions."""

import re
import urllib.parse
import urllib
import string
from publicsuffixlist import PublicSuffixList

class UrlParseError(Exception):
    pass

def GenerateSafeChars():
    unfiltered_chars = string.digits + string.ascii_letters + string.punctuation
    filtered_list = [c for c in unfiltered_chars if c not in '%#']
    return ''.join(filtered_list)

class ExpressionGenerator(object):
    HEX = re.compile(r'^0x([a-fA-F0-9]+)$')
    OCT = re.compile(r'^0([0-7]+)$')
    DEC = re.compile(r'^(\d+)$')
    IP_WITH_TRAILING_SPACE = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ')
    POSSIBLE_IP = re.compile(r'^(?i)((?:0x[0-9a-f]+|[0-9\\.])+)$')
    FIND_BAD_OCTAL_REGEXP = re.compile(r'(^|\.)0\d*[89]')
    HOST_PORT_REGEXP = re.compile(r'^(?:.*@)?(?P<host>[^:]*)(:(?P<port>\d+))?$')
    SAFE_CHARS = GenerateSafeChars()
    DEFAULT_PORTS = {'http': '80', 'https': '443', 'ftp': '21'}

    def __init__(self, url):
        parse_exception = UrlParseError('failed to parse URL "%s"' % (url,))
        canonical_url = ExpressionGenerator.CanonicalizeUrl(url)
        if not canonical_url:
            raise parse_exception

        self._host_lists = []
        self._path_exprs = []
        url_split = urllib.parse.urlsplit(canonical_url)
        canonical_host, canonical_path = url_split[1], url_split[2]
        self._MakeHostLists(canonical_host, parse_exception)
        if url_split[3]:
            self._path_exprs.append(canonical_path + '?' + url_split[3])
        self._path_exprs.append(canonical_path)

        path_parts = canonical_path.rstrip('/').lstrip('/').split('/')[:3]
        if canonical_path.count('/') < 4:
            path_parts.pop()
        while path_parts:
            self._path_exprs.append('/' + '/'.join(path_parts) + '/')
            path_parts.pop()
        if canonical_path != '/':
            self._path_exprs.append('/')

    @staticmethod
    def CanonicalizeUrl(url):
        tmp_pos = url.find('#')
        if tmp_pos >= 0:
            url = url[:tmp_pos]
        url = url.lstrip().rstrip()
        url = url.replace('\t', '').replace('\r', '').replace('\n', '')
        url = ExpressionGenerator._Escape(url)
        url_split = urllib.parse.urlsplit(url)
        if not url_split.scheme:
            url = 'http://' + url
            url_split = urllib.parse.urlsplit(url)
        url_scheme = url_split.scheme.lower()
        if url_scheme not in ExpressionGenerator.DEFAULT_PORTS:
            return None

        m = ExpressionGenerator.HOST_PORT_REGEXP.match(url_split.netloc)
        if not m:
            return None
        host, port = m.group('host'), m.group('port')
        canonical_host = ExpressionGenerator.CanonicalizeHost(host)
        if not canonical_host:
            return None

        if port and port != ExpressionGenerator.DEFAULT_PORTS[url_scheme]:
            canonical_host += ':' + port
        canonical_path = ExpressionGenerator.CanonicalizePath(url_split.path)
        canonical_url = url_split.scheme + '://' + canonical_host + canonical_path
        if url_split.query != '' or url.endswith('?'):
            canonical_url += '?' + url_split.query
        return canonical_url

    @staticmethod
    def CanonicalizePath(path):
        if not path:
            return '/'
        if path[0] != '/':
            path = '/' + path
        path = ExpressionGenerator._Escape(path)
        path_components = []
        for path_component in path.split('/'):
            if path_component == '..':
                if len(path_components) > 0:
                    path_components.pop()
            elif path_component != '.' and path_component != '':
                path_components.append(path_component)
        canonical_path = '/' + '/'.join(path_components)
        if path.endswith('/') and not canonical_path.endswith('/'):
            canonical_path += '/'
        return canonical_path

    @staticmethod
    def CanonicalizeHost(host):
        if not host:
            return None
        host = ExpressionGenerator._Escape(host.lower())
        ip = ExpressionGenerator.CanonicalizeIp(host)
        if ip:
            host = ip
        else:
            host_split = [part for part in host.split('.') if part]
            if len(host_split) < 2:
                return None
            host = '.'.join(host_split)
        return host

    @staticmethod
    def CanonicalizeIp(host):
        if len(host) <= 15:
            m = ExpressionGenerator.IP_WITH_TRAILING_SPACE.match(host)
            if m:
                host = m.group(1)
        if not ExpressionGenerator.POSSIBLE_IP.match(host):
            return None
        allow_octal = not ExpressionGenerator.FIND_BAD_OCTAL_REGEXP.search(host)
        host_split = [part for part in host.split('.') if part]
        if len(host_split) > 4:
            return None
        ip = []
        for i in range(len(host_split)):
            m = ExpressionGenerator.HEX.match(host_split[i])
            if m:
                base = 16
            else:
                m = ExpressionGenerator.OCT.match(host_split[i])
                if m and allow_octal:
                    base = 8
                else:
                    m = ExpressionGenerator.DEC.match(host_split[i])
                    if m:
                        base = 10
                    else:
                        return None
            n = int(m.group(1), base)
            if n > 255:
                if i < len(host_split) - 1:
                    n &= 0xff
                    ip.append(n)
                else:
                    bytes = []
                    shift = 0
                    while n > 0 and len(bytes) < 4:
                        bytes.append(n & 0xff)
                        n >>= 8
                    if len(ip) + len(bytes) > 4:
                        return None
                    bytes.reverse()
                    ip.extend(bytes)
            else:
                ip.append(n)
        while len(ip) < 4:
            ip.append(0)
        return '%u.%u.%u.%u' % tuple(ip)

    def Expressions(self):
        for host_parts in self._host_lists:
            host = '.'.join(host_parts)
            for p in self._path_exprs:
                yield Expression(host, p)

    @staticmethod
    def _Escape(unescaped_str):
        unquoted = urllib.parse.unquote(unescaped_str)
        while unquoted != unescaped_str:
            unescaped_str = unquoted
            unquoted = urllib.parse.unquote(unquoted)
        return urllib.parse.quote(unquoted, ExpressionGenerator.SAFE_CHARS)

    def _MakeHostLists(self, host, parse_exception):
        ip = ExpressionGenerator.CanonicalizeIp(host)
        if ip is not None:
            self._host_lists.append([ip])
            return
        host_split = [part for part in host.split('.') if part]
        if len(host_split) < 2:
            raise parse_exception
        start = len(host_split) - 5
        stop = len(host_split) - 1
        if start <= 0:
            start = 1
        self._host_lists.append(host_split)
        for i in range(start, stop):
            self._host_lists.append(host_split[i:])

class Expression(object):
    def __init__(self, host, path):
        self._host = host
        self._path = path
        self._value = host + path

    def __str__(self):
        return self.Value()

    def __repr__(self):
        return self.Value()

    def Value(self):
        return self._value

