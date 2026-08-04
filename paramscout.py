#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ParamScout - Advanced HTTP Parameter Discovery Tool
Author: SYLHETYHACKVENGER (THE-ERROR808)

  _____  _______  ______ _______ _______      _______ _______  _____  _     _ _______
 |_____] |_____| |_____/ |_____| |  |  |      |______ |       |     | |     |    |
 |       |     | |    \\_ |     | |  |  |      ______| |_____  |_____| |_____|    |

ParamScout is a powerful HTTP parameter discovery tool that
helps security researchers and penetration testers find hidden
parameters in web applications. It uses advanced anomaly
detection techniques and multiple passive sources to discover
parameters efficiently.
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import sys
import tempfile
import time
import signal
import warnings
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs
from collections import defaultdict

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
except ImportError as e:
    sys.stdout.write(f"[!] Missing required module: {e}\n")
    sys.stdout.write("[!] Please install: pip install requests\n")
    sys.exit(1)

try:
    from dicttoxml import dicttoxml
except ImportError:
    dicttoxml = None

warnings.filterwarnings('ignore')

# Thread-safe kill signal
kill_event = threading.Event()

def signal_handler(sig, frame):
    sys.stdout.write('\n[!] Exiting...\n')
    kill_event.set()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

colors = True
machine = sys.platform
if machine.lower().startswith(('os', 'win', 'darwin', 'ios')):
    colors = False
if not colors:
    white = green = red = yellow = end = back = info = que = bad = good = run = res = ''
else:
    white = '\033[97m'
    green = '\033[92m'
    red = '\033[91m'
    yellow = '\033[93m'
    end = '\033[0m'
    back = '\033[7;91m'
    info = '\033[1;93m[!]\033[0m'
    que = '\033[1;94m[?]\033[0m'
    bad = '\033[1;91m[-]\033[0m'
    good = '\033[1;32m[+]\033[0m'
    run = '\033[1;97m[*]\033[0m'
    res = '\033[1;92m[✓]\033[0m'

var = {}
QUIET_MODE = False
MAX_RETRIES = 3
LOCK = threading.Lock()

# Rotating User Agents
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
]

def custom_print(*args, **kwargs):
    if not QUIET_MODE:
        if args:
            sys.stdout.write(' '.join(str(arg) for arg in args) + '\n')
            sys.stdout.flush()

def show_banner():
    banner = f"""
{green}
  _____  _______  ______ _______ _______      _______ _______  _____  _     _ _______
 |_____] |_____| |_____/ |_____| |  |  |      |______ |       |     | |     |    |
 |       |     | |    \\_ |     | |  |  |      ______| |_____  |_____| |_____|    |
{end}

{white}ParamScout - Advanced HTTP Parameter Discovery Tool{end}
{white}Author: SYLHETYHACKVENGER (THE-ERROR808){end}

{white}ParamScout is a powerful HTTP parameter discovery tool that
helps security researchers and penetration testers find hidden
parameters in web applications. It uses advanced anomaly
detection techniques and multiple passive sources to discover
parameters efficiently.{end}
"""
    custom_print(banner)

def compatible_path(path):
    if sys.platform.lower().startswith('win'):
        return path.replace('/', '\\')
    return path

def reader(path, mode='string'):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as file:
            if mode == 'lines':
                return [line.rstrip('\n') for line in file if line.strip()]
            else:
                return ''.join([line for line in file])
    except:
        return None

def prompt(default=None):
    editor = 'nano'
    with tempfile.NamedTemporaryFile(mode='r+') as tmpfile:
        if default:
            tmpfile.write(default)
            tmpfile.flush()
        child_pid = os.fork()
        is_child = child_pid == 0
        if is_child:
            os.execvp(editor, [editor, tmpfile.name])
        else:
            os.waitpid(child_pid, 0)
            tmpfile.seek(0)
            return tmpfile.read().strip()

def random_str(n):
    return ''.join(str(random.choice(range(10))) for _ in range(n))

def remove_tags(html):
    return re.sub(r'(?s)<.*?>', '', html)

def diff_map(body_1, body_2):
    sig = []
    lines_1, lines_2 = body_1.split('\n'), body_2.split('\n')
    for line_1, line_2 in zip(lines_1, lines_2):
        if line_1 == line_2:
            sig.append(line_1)
    return sig

def populate(array):
    return {name: '1' * (6 - len(str(i))) + str(i) for i, name in enumerate(array)}

def slicer(dic, n=2):
    if n <= 0:
        n = 1
    listed = list(dic.items())
    if not listed:
        return []
    k, m = divmod(len(dic), n)
    return [dict(listed[i * k + min(i, m):(i + 1) * k + min(i + 1, m)]) for i in range(n)]

def confirm(array_of_dicts, usable):
    param_groups = []
    for dic in array_of_dicts:
        if len(dic) == 1:
            usable.append(dic)
        else:
            param_groups.append(dic)
    return param_groups

def extract_js(response):
    scripts = []
    for part in re.split('(?i)<script[> ]', response):
        actual_parts = re.split('(?i)</script>', part, maxsplit=2)
        if len(actual_parts) > 1:
            scripts.append(actual_parts[0])
    return scripts

def parse_headers(string):
    result = {}
    for line in string.split('\n'):
        if len(line) > 1:
            splitted = line.split(':')
            if len(splitted) >= 2:
                result[splitted[0].strip()] = ':'.join(splitted[1:]).strip()
    return result

def parse_request(string):
    result = {}
    match = re.search(r'(?:([a-zA-Z0-9]+) ([^ ]+) [^ ]+\n)?([\s\S]+\n)\n?([\s\S]+)?', string)
    if match:
        result['method'] = match.group(1) or 'GET'
        result['path'] = match.group(2) or '/'
        result['headers'] = parse_headers(match.group(3) or '')
        if 'Host' in result['headers']:
            result['url'] = 'http://' + result['headers']['Host'] + result['path']
        else:
            result['url'] = 'http://localhost' + result['path']
        result['data'] = match.group(4) or ''
    return result

def create_query_string(params):
    query_string = ''
    for param in params:
        pair = param + '=' + random_str(4) + '&'
        query_string += pair
    if query_string.endswith('&'):
        query_string = query_string[:-1]
    return '?' + query_string

def get_params(include):
    params = {}
    if include:
        if isinstance(include, dict):
            return include
        if isinstance(include, str) and include.startswith('{'):
            try:
                params = json.loads(include.replace("'", '"'))
                if not isinstance(params, dict):
                    return {}
                return params
            except:
                return {}
        elif isinstance(include, str):
            cleaned = include.split('?')[-1]
            parts = cleaned.split('&')
            for part in parts:
                if '=' in part:
                    each = part.split('=', 1)
                    params[each[0]] = each[1] if len(each) > 1 else ''
    return params

def dict_to_xml(dict_obj):
    if dicttoxml:
        try:
            return dicttoxml(dict_obj, root=False, attr_type=False).decode('utf-8')
        except:
            pass
    # Fallback custom XML converter
    xml = ""
    for key, value in dict_obj.items():
        if isinstance(value, dict):
            xml += f"<{key}>{dict_to_xml(value)}</{key}>"
        elif isinstance(value, list):
            for item in value:
                xml += f"<{key}>{dict_to_xml(item)}</{key}>"
        else:
            xml += f"<{key}>{value}</{key}>"
    return xml

def extract_headers(headers):
    headers = headers.replace('\\n', '\n')
    return parse_headers(headers)

def get_session():
    """Create a session with retry strategy and connection pooling"""
    session = requests.Session()
    
    # Retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
    )
    
    # Mount adapters
    adapter = HTTPAdapter(
        pool_connections=10,
        pool_maxsize=10,
        max_retries=retry_strategy
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.keep_alive = False
    
    return session

def stable_request(url, headers):
    parsed = urlparse(url)
    redirects_allowed = False if var.get('disable_redirects', False) else True
    scheme, host, path = parsed.scheme, parsed.netloc, parsed.path
    schemes = (['https', 'http'] if scheme == 'https' else ['http', 'https'])
    
    headers = headers.copy() if headers else {}
    headers['User-Agent'] = random.choice(USER_AGENTS)
    
    session = get_session()
    
    for scheme in schemes:
        try:
            response = session.get(
                scheme + '://' + host + path,
                headers=headers,
                verify=False,
                timeout=10,
                allow_redirects=redirects_allowed)
            content_type = response.headers.get('Content-Type', '')
            if any(x in content_type for x in ['text', 'html', 'json', 'xml']):
                session.close()
                return response.url
            custom_print('%s URL doesn\'t seem to be a webpage. Skipping.' % info)
            session.close()
            return None
        except:
            continue
    session.close()
    return None

def connection_refused():
    if var.get('stable', False):
        custom_print('%s Hit rate limit, stabilizing the connection' % bad)
        kill_event.clear()
        time.sleep(30)
        return 'retry'
    custom_print('%s Target has rate limiting in place, please use --stable switch' % bad)
    return 'kill'

def error_handler(response, factors):
    if isinstance(response, requests.models.Response):
        status = response.status_code
        
        # Handle 413 - Payload Too Large
        if status == 413:
            with LOCK:
                var['chunks'] = max(10, var.get('chunks', 250) // 2)
            custom_print('%s Payload too large, reducing chunk size to %d' % (info, var['chunks']))
            return 'retry'
        
        # Handle 414 - URI Too Long
        if status == 414:
            with LOCK:
                var['chunks'] = max(5, var.get('chunks', 250) // 3)
            custom_print('%s URI too long, reducing chunk size to %d' % (info, var['chunks']))
            return 'retry'
        
        if status in (400, 418, 429, 500, 502, 503, 504):
            if not var.get('healthy_url', False):
                return 'ok'
            if status in (500, 502, 503, 504):
                kill_event.set()
                custom_print('%s Server error (%d), try --stable switch' % (bad, status))
                return 'kill'
            elif status in (429, 418):
                if var.get('stable', False):
                    time.sleep(random.uniform(5, 15))
                    return 'retry'
                custom_print('%s Target has a rate limit in place, try --stable switch' % bad)
                return 'kill'
            else:
                if factors.get('same_code') != status:
                    with LOCK:
                        var['bad_req_count'] = var.get('bad_req_count', 0) + 1
                    if var['bad_req_count'] > 20:
                        kill_event.set()
                        custom_print('%s Server received a bad request. Try decreasing the chunk size with -c option' % bad)
                        return 'kill'
                else:
                    return 'ok'
    else:
        if isinstance(response, str):
            if 'Timeout' in response:
                if var.get('timeout', 15) > 30:
                    kill_event.set()
                    custom_print('%s Connection timed out, unable to increase timeout further' % bad)
                    custom_print('%s Target might have a rate limit in place, try --stable switch' % bad)
                    return 'kill'
                else:
                    custom_print('%s Connection timed out, increased timeout by 5 seconds' % bad)
                    with LOCK:
                        var['timeout'] = var.get('timeout', 15) + 5
                    return 'retry'
            elif 'ConnectionRefused' in response:
                return connection_refused()
            elif "'" in response:
                custom_print('%s Encountered an error: %s' % (bad, response.split("'")[1]))
                return 'kill'
    return 'ok'

def requester(request, payload=None):
    if payload is None:
        payload = {}
    
    rate_limit = var.get('rate_limit', 9999)
    if 0 < rate_limit < 9999:
        time.sleep(1.0 / max(rate_limit, 1))
    
    if request.get('include') and len(request.get('include', '')) != 0:
        if isinstance(request['include'], dict):
            payload.update(request['include'])
    
    if var.get('stable', False):
        var['delay'] = random.uniform(3, 10)
    
    time.sleep(var.get('delay', 0))
    url = request['url']
    
    if kill_event.is_set():
        return 'killed'
    
    headers = request['headers'].copy() if request.get('headers') else {}
    headers['User-Agent'] = random.choice(USER_AGENTS)
    
    session = get_session()
    
    try:
        method = request['method']
        timeout = var.get('timeout', 15)
        verify_ssl = var.get('verify_ssl', False)
        
        # Check response size limit
        max_size = var.get('max_response_size', 20_000_000)  # 20MB default
        
        if method == 'GET':
            response = session.get(url, params=payload, headers=headers, verify=verify_ssl, allow_redirects=False, timeout=timeout)
        elif method == 'JSON':
            headers['Content-Type'] = 'application/json'
            include_str = var.get('include', '')
            if isinstance(include_str, str) and '$paramscout$' in include_str:
                payload_str = include_str.replace('$paramscout$', json.dumps(payload).rstrip('}').lstrip('{'))
                response = session.post(url, data=payload_str, headers=headers, verify=verify_ssl, allow_redirects=False, timeout=timeout)
            else:
                response = session.post(url, json=payload, headers=headers, verify=verify_ssl, allow_redirects=False, timeout=timeout)
        elif method == 'XML':
            headers['Content-Type'] = 'application/xml'
            include_str = var.get('include', '')
            if isinstance(include_str, str):
                payload_str = include_str.replace('$paramscout$', dict_to_xml(payload))
                response = session.post(url, data=payload_str, headers=headers, verify=verify_ssl, allow_redirects=False, timeout=timeout)
            else:
                response = session.post(url, data=dict_to_xml(payload), headers=headers, verify=verify_ssl, allow_redirects=False, timeout=timeout)
        else:
            response = session.post(url, data=payload, headers=headers, verify=verify_ssl, allow_redirects=False, timeout=timeout)
        
        # Check response size
        if len(response.content) > max_size:
            custom_print('%s Response too large (>%dMB), truncating' % (info, max_size // 1_000_000))
            response._content = response.content[:max_size]
        
        session.close()
        return response
    except requests.exceptions.Timeout:
        session.close()
        return 'Timeout'
    except requests.exceptions.ConnectionError:
        session.close()
        return 'ConnectionRefused'
    except Exception as e:
        session.close()
        return str(e)

def define(response_1, response_2, param, value, wordlist):
    factors = {
        'same_code': None,
        'same_body': None,
        'same_plaintext': None,
        'lines_num': None,
        'lines_diff': None,
        'same_headers': None,
        'same_redirect': None,
        'param_missing': None,
        'value_missing': None
    }
    
    if not (isinstance(response_1, requests.models.Response) and isinstance(response_2, requests.models.Response)):
        return factors
    
    body_1, body_2 = response_1.text, response_2.text
    
    if response_1.status_code == response_2.status_code:
        factors['same_code'] = response_1.status_code
    
    if response_1.headers.keys() == response_2.headers.keys():
        factors['same_headers'] = sorted(list(response_1.headers.keys()))
    
    if var.get('disable_redirects', False):
        if response_1.headers.get('Location', '') == response_2.headers.get('Location', ''):
            factors['same_redirect'] = urlparse(response_1.headers.get('Location', '')).path
    elif urlparse(response_1.url).path == urlparse(response_2.url).path:
        factors['same_redirect'] = urlparse(response_1.url).path
    else:
        factors['same_redirect'] = ''
    
    if response_1.text == response_2.text:
        factors['same_body'] = response_1.text
    elif response_1.text.count('\n') == response_2.text.count('\n'):
        factors['lines_num'] = response_1.text.count('\n')
    elif remove_tags(body_1) == remove_tags(body_2):
        factors['same_plaintext'] = remove_tags(body_1)
    elif body_1 and body_2 and body_1.count('\\n') == body_2.count('\\n'):
        factors['lines_diff'] = diff_map(body_1, body_2)
    
    if param not in response_2.text:
        factors['param_missing'] = [word for word in wordlist if word in response_2.text]
    
    if value not in response_2.text:
        factors['value_missing'] = True
    
    return factors

def compare(response, factors, params):
    if response == '' or isinstance(response, str):
        return ('', [], '')
    
    if not isinstance(response, requests.models.Response):
        return ('', [], '')
    
    these_headers = sorted(list(response.headers.keys()))
    
    if factors.get('same_code') is not None and response.status_code != factors['same_code']:
        return ('http code', params, 'same_code')
    
    if factors.get('same_headers') is not None and these_headers != factors['same_headers']:
        return ('http headers', params, 'same_headers')
    
    if var.get('disable_redirects', False):
        if factors.get('same_redirect') is not None:
            loc = urlparse(response.headers.get('Location', '')).path
            if loc != factors['same_redirect']:
                return ('redirection', params, 'same_redirect')
    elif factors.get('same_redirect') is not None and 'Location' in response.headers:
        loc = urlparse(response.headers.get('Location', '')).path
        if loc != factors['same_redirect']:
            return ('redirection', params, 'same_redirect')
    
    if factors.get('same_body') is not None and response.text != factors['same_body']:
        return ('body length', params, 'same_body')
    
    if factors.get('lines_num') is not None and response.text.count('\n') != factors['lines_num']:
        return ('number of lines', params, 'lines_num')
    
    if factors.get('same_plaintext') is not None and remove_tags(response.text) != factors['same_plaintext']:
        return ('text length', params, 'same_plaintext')
    
    if factors.get('lines_diff') is not None:
        for line in factors['lines_diff']:
            if line not in response.text:
                return ('lines', params, 'lines_diff')
    
    if factors.get('param_missing') is not None:
        for param in params.keys():
            if len(param) < 5:
                continue
            if param not in factors['param_missing']:
                if re.search(r'[\'"\s]%s[\'"\s]' % re.escape(param), response.text):
                    return ('param name reflection', params, 'param_missing')
    
    if factors.get('value_missing') is not None:
        for value in params.values():
            if not isinstance(value, str) or len(value) != 6:
                continue
            if value in response.text:
                if re.search(r'[\'"\s]%s[\'"\s]' % re.escape(value), response.text):
                    return ('param value reflection', params, 'value_missing')
    
    return ('', [], '')

def bruter(request, factors, params, mode='bruteforce', retry_count=0):
    if kill_event.is_set():
        return []
    
    if retry_count >= MAX_RETRIES:
        return []
    
    response = requester(request, params)
    conclusion = error_handler(response, factors)
    
    if conclusion == 'retry':
        return bruter(request, factors, params, mode=mode, retry_count=retry_count + 1)
    elif conclusion == 'kill':
        kill_event.set()
        return []
    
    comparison_result = compare(response, factors, params)
    if mode == 'verify':
        return comparison_result[0]
    return comparison_result[1]

BURP_REGEX = re.compile(r'''(?m)^    <url><!\[CDATA\[(.+?)\]\]></url>
    <host ip="[^"]*">[^<]+</host>
    <port>[^<]*</port>
    <protocol>[^<]*</protocol>
    <method><!\[CDATA\[(.+?)\]\]></method>
    <path>.*</path>
    <extension>(.*)</extension>
    <request base64="(?:false|true)"><!\[CDATA\[([\s\S]+?)]]></request>
    <status>([^<]*)</status>
    <responselength>([^<]*)</responselength>
    <mimetype>([^<]*)</mimetype>''')

def burp_import(path):
    requests_list = []
    content = reader(path)
    if not content:
        return requests_list
    matches = BURP_REGEX.finditer(content)
    for match in matches:
        request = parse_request(match.group(4))
        headers = request.get('headers', {})
        if match.group(7) in ('HTML', 'JSON'):
            requests_list.append({
                'url': match.group(1),
                'method': match.group(2),
                'extension': match.group(3),
                'headers': headers,
                'include': request.get('data', ''),
                'code': match.group(5),
                'length': match.group(6),
                'mime': match.group(7)
            })
    return requests_list

def urls_import(path, method, headers, include):
    requests_list = []
    urls = reader(path, mode='lines')
    if not urls:
        return requests_list
    for url in urls:
        if url.startswith(('http://', 'https://')):
            requests_list.append({
                'url': url,
                'method': method,
                'headers': headers.copy() if headers else {},
                'data': include
            })
    return requests_list

def request_import(path):
    result = []
    content = reader(path)
    if content:
        result.append(parse_request(content))
    return result

def importer(path, method, headers, include):
    content = reader(path)
    if not content:
        return []
    for line in content.split('\n')[:5]:
        if line.startswith('<?xml'):
            return burp_import(path)
        elif line.startswith(('http://', 'https://')):
            return urls_import(path, method, headers, include)
        elif line.startswith(('GET', 'POST')):
            return request_import(path)
    return []

def json_export(result):
    try:
        with open(var['json_file'], 'w+', encoding='utf8') as json_output:
            json.dump(result, json_output, sort_keys=True, indent=4, default=str)
    except Exception as e:
        custom_print('%s Error exporting JSON: %s' % (bad, str(e)))

def burp_export(result):
    proxy = ('' if ':' in var['burp_proxy'] else '127.0.0.1:') + var['burp_proxy']
    proxies = {'http': 'http://' + proxy, 'https': 'https://' + proxy}
    session = get_session()
    for url, data in result.items():
        try:
            headers = data.get('headers', {})
            params = data.get('params', [])
            method = data.get('method', 'GET')
            if method == 'GET':
                session.get(url, params=populate(params), headers=headers, proxies=proxies, verify=False, timeout=5)
            elif method == 'POST':
                session.post(url, data=populate(params), headers=headers, proxies=proxies, verify=False, timeout=5)
            elif method == 'JSON':
                session.post(url, json=populate(params), headers=headers, proxies=proxies, verify=False, timeout=5)
        except:
            pass
    session.close()

def text_export(result):
    try:
        with open(var['text_file'], 'a+', encoding='utf8') as text_file:
            for url, data in result.items():
                clean_url = url.lstrip('/')
                params = data.get('params', [])
                method = data.get('method', 'GET')
                if method == 'JSON':
                    text_file.write(clean_url + '\t' + json.dumps(populate(params)) + '\n')
                else:
                    query_string = create_query_string(params)
                    if '?' in clean_url:
                        query_string = query_string.replace('?', '&', 1)
                    if method == 'GET':
                        text_file.write(clean_url + query_string + '\n')
                    elif method == 'POST':
                        text_file.write(clean_url + '\t' + query_string + '\n')
    except Exception as e:
        custom_print('%s Error exporting text: %s' % (bad, str(e)))

def exporter(result):
    if var.get('json_file'):
        json_export(result)
    if var.get('text_file'):
        text_export(result)
    if var.get('burp_proxy'):
        burp_export(result)

def commoncrawl(host, page=0):
    these_params = set()
    try:
        session = get_session()
        response = session.get(
            'http://index.commoncrawl.org/CC-MAIN-2024-42-index?url=*.%s&fl=url&page=%s&limit=10000' % (host, page),
            verify=False, timeout=30,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        ).text
        session.close()
        if response.startswith('<!DOCTYPE html>'):
            return ([], False, 'commoncrawl')
        urls = response.split('\n')
        for url in urls:
            if url:
                for param in urlparse(url).query.split('&'):
                    if param:
                        these_params.add(param.split('=')[0])
        return (these_params, True, 'commoncrawl')
    except:
        return ([], False, 'commoncrawl')

def otx(host, page):
    these_params = set()
    try:
        session = get_session()
        data = session.get(
            'https://otx.alienvault.com/api/v1/indicators/hostname/%s/url_list?limit=50&page=%d' % (host, page+1),
            verify=False, timeout=30,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        ).json()
        session.close()
        if 'url_list' not in data:
            return (these_params, False, 'otx')
        for obj in data['url_list']:
            for param in urlparse(obj['url']).query.split('&'):
                if param:
                    these_params.add(param.split('=')[0])
        return (these_params, data.get('has_next', False), 'otx')
    except:
        return (these_params, False, 'otx')

def wayback(host, page):
    payload = {'url': host, 'matchType': 'host', 'collapse': 'urlkey', 'fl': 'original', 'page': page, 'limit': 10000}
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        these_params = set()
        session = get_session()
        response = session.get(
            'http://web.archive.org/cdx/search?filter=mimetype:text/html&filter=statuscode:200',
            params=payload, headers=headers, verify=False, timeout=30
        ).text
        session.close()
        if not response:
            return (these_params, False, 'wayback')
        urls = filter(None, response.split('\n'))
        for url in urls:
            for param in urlparse(url).query.split('&'):
                if param:
                    these_params.add(param.split('=')[0])
        return (these_params, True, 'wayback')
    except:
        return (these_params, False, 'wayback')

def fetch_params(host):
    available_plugins = {'commoncrawl': commoncrawl, 'otx': otx, 'wayback': wayback}
    page = 0
    progress = 0
    params = {}
    while available_plugins and page <= 10:
        try:
            with ThreadPoolExecutor(max_workers=min(len(available_plugins), 3)) as threadpool:
                futures = [threadpool.submit(func, host, page) for func in available_plugins.values()]
                for each in as_completed(futures, timeout=60):
                    if progress < 98:
                        progress += 3
                    this_result = each.result()
                    if not this_result[1]:
                        progress += ((10 - page) * 10 / 3)
                        if this_result[2] in available_plugins:
                            del available_plugins[this_result[2]]
                    if len(this_result[0]) > 1:
                        if not params:
                            params = this_result[0]
                        else:
                            params.update(this_result[0])
                    sys.stdout.write('\r%s Progress: %i%%' % (info, min(progress, 100)))
                    sys.stdout.flush()
        except:
            pass
        page += 1
    custom_print('\r%s Progress: 100%%' % info)
    return params

RE_WORDS = re.compile(r'[A-Za-z][A-Za-z0-9_]*')
RE_NOT_JUNK = re.compile(r'^[A-Za-z0-9_]+$')
RE_INPUTS = re.compile(r'''(?i)<(?:input|textarea)[^>]+?(?:id|name)=["']?([^"'\s>]+)''')
RE_EMPTY_VARS = re.compile(r'''(?:[;\n]|\bvar|\blet)(\w+)\s*=\s*(?:['"`]{1,2}|true|false|null)''')
RE_MAP_KEYS = re.compile(r'''['"](\w+?)['"]\s*:\s*['"`]''')

def is_not_junk(param):
    return RE_NOT_JUNK.match(param) is not None

def heuristic(raw_response, wordlist):
    words_exist = False
    potential_params = []
    headers, response = raw_response.headers, raw_response.text
    
    content_type = headers.get('content-type', '')
    if content_type.startswith(('application/json', 'text/plain')):
        if len(response) < 200:
            response_lower = response.lower()
            if any(word in response_lower for word in ['required', 'missing', 'not found', 'requires']):
                if any(word in response_lower for word in ['param', 'parameter', 'field']):
                    if not QUIET_MODE:
                        custom_print('%s The endpoint seems to require certain parameters to function. Check the response and use the --include option appropriately for better results.' % info)
            words_exist = True
            potential_params = RE_WORDS.findall(response)
    
    input_names = RE_INPUTS.findall(response)
    potential_params.extend(input_names)
    
    for script in extract_js(response):
        empty_vars = RE_EMPTY_VARS.findall(script)
        potential_params.extend(empty_vars)
        map_keys = RE_MAP_KEYS.findall(script)
        potential_params.extend(map_keys)
    
    if not potential_params:
        return [], words_exist
    
    found = set()
    for word in potential_params:
        if is_not_junk(word) and word not in found:
            found.add(word)
            if word in wordlist:
                wordlist.remove(word)
            wordlist.insert(0, word)
    
    return list(found), words_exist

def detect_casing(string):
    delimiter = ""
    casing = ""
    if string.islower():
        casing = "l"
    elif string.isupper():
        casing = "u"
    else:
        casing = "c" if string[0].islower() else "p"
    if "-" in string:
        delimiter = "-"
    elif "_" in string:
        delimiter = "_"
    elif "." in string:
        delimiter = "."
    return delimiter, casing

def transform(parts, delimiter, casing):
    if len(parts) == 1:
        if casing == "l":
            return parts[0].lower()
        elif casing == "u":
            return parts[0].upper()
        return parts[0]
    result = []
    for i, part in enumerate(parts):
        if casing == "l":
            transformed = part.lower()
        elif casing == "u":
            transformed = part.upper()
        elif casing == "c":
            transformed = part.lower() if i == 0 else part.lower().title()
        else:
            transformed = part.lower().title()
        result.append(transformed)
    return delimiter.join(result)

def handle(text):
    if "-" in text:
        return text.split("-")
    elif "_" in text:
        return text.split("_")
    elif "." in text:
        return text.split(".")
    if not text.islower() and not text.isupper():
        parts = []
        temp = ""
        for char in text:
            if not char.isupper():
                temp += char
            else:
                if temp:
                    parts.append(temp)
                temp = char
        if temp:
            parts.append(temp)
        return parts
    return [text]

def covert_to_case(string, delimiter, casing):
    parts = handle(string)
    return transform(parts, delimiter, casing)

def prepare_requests(args):
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }
    result = []
    if args.headers:
        if args.headers is True:
            headers = extract_headers(prompt())
        else:
            headers = extract_headers(args.headers)
    if var['method'] == 'JSON':
        headers['Content-type'] = 'application/json'
    if args.url:
        params = get_params(args.include)
        result.append({'url': args.url, 'method': var['method'], 'headers': headers, 'include': params})
    elif args.import_file:
        if args.import_file is True:
            path = prompt()
        else:
            path = args.import_file
        result = importer(path, var['method'], headers, args.include)
    return result

def narrower(request, factors, param_groups):
    anomalous_params = []
    try:
        with ThreadPoolExecutor(max_workers=max(1, var.get('threads', 5))) as threadpool:
            futures = [threadpool.submit(bruter, request, factors, params) for params in param_groups]
            for i, future in enumerate(as_completed(futures, timeout=300)):
                try:
                    result = future.result(timeout=60)
                    if result:
                        anomalous_params.extend(slicer(result))
                except concurrent.futures.TimeoutError:
                    continue
                except Exception:
                    continue
                if kill_event.is_set():
                    return anomalous_params
                sys.stdout.write('\r%s Processing chunks: %i/%-6i' % (info, i + 1, len(param_groups)))
                sys.stdout.flush()
    except:
        pass
    custom_print('')
    return anomalous_params

def initialize(request, wordlist, single_url=False):
    url = request['url']
    if not url.startswith('http'):
        custom_print('%s %s is not a valid URL' % (bad, url))
        return 'skipped'
    custom_print('%s Probing the target for stability' % run)
    request['url'] = stable_request(url, request['headers'])
    var['healthy_url'] = True
    if not request['url']:
        return 'skipped'
    
    fuzz = "z" + random_str(6)
    response_1 = requester(request, {fuzz[:-1]: fuzz[::-1][:-1]})
    if isinstance(response_1, str):
        return 'skipped'
    
    var['healthy_url'] = response_1.status_code not in (400, 413, 414, 418, 429, 500, 502, 503, 504)
    if not var['healthy_url']:
        custom_print('%s Target returned HTTP %i, this may cause problems.' % (bad, response_1.status_code))
    
    if single_url:
        custom_print('%s Analysing HTTP response for anomalies' % run)
    
    response_2 = requester(request, {fuzz[:-1]: fuzz[::-1][:-1]})
    if isinstance(response_1, str) or isinstance(response_2, str):
        return 'skipped'
    
    found, words_exist = heuristic(response_1, wordlist)
    factors = define(response_1, response_2, fuzz, fuzz[::-1], wordlist)
    
    zzuf = "z" + random_str(6)
    response_3 = requester(request, {zzuf[:-1]: zzuf[::-1][:-1]})
    while True:
        reason = compare(response_3, factors, {zzuf[:-1]: zzuf[::-1][:-1]})[2]
        if not reason:
            break
        factors[reason] = None
    
    if found:
        num = len(found)
        if words_exist:
            custom_print('%s Extracted %i parameters from response for testing' % (good, num))
        else:
            s = 's' if num > 1 else ''
            custom_print('%s Extracted %i parameter%s from response for testing: %s' % (good, num, s, ', '.join(found[:10])))
            if num > 10:
                custom_print('%s ... and %i more' % (info, num - 10))
    
    if single_url:
        custom_print('%s Logicforcing the URL endpoint' % run)
    
    populated = populate(wordlist)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_dir = os.path.join(script_dir, 'assets', 'db')
    special_file = os.path.join(db_dir, 'special.json')
    if os.path.exists(special_file):
        try:
            with open(special_file, 'r') as f:
                populated.update(json.load(f))
        except:
            pass
    
    chunks = max(1, var.get('chunks', 250))
    param_groups = slicer(populated, max(1, int(len(wordlist) / chunks)))
    prev_chunk_count = len(param_groups)
    last_params = []
    
    while True:
        param_groups = narrower(request, factors, param_groups)
        if len(param_groups) > prev_chunk_count:
            response_3 = requester(request, {zzuf[:-1]: zzuf[::-1][:-1]})
            if compare(response_3, factors, {zzuf[:-1]: zzuf[::-1][:-1]})[0] != '':
                custom_print('%s Webpage is returning different content on each request. Skipping.' % bad)
                return []
        if kill_event.is_set():
            return 'skipped'
        param_groups = confirm(param_groups, last_params)
        prev_chunk_count = len(param_groups)
        if not param_groups:
            break
    
    confirmed_params = []
    for param in last_params:
        reason = bruter(request, factors, param, mode='verify')
        if reason:
            name = list(param.keys())[0]
            confirmed_params.append(name)
            if single_url:
                custom_print('%s parameter detected: %s, based on: %s' % (res, name, reason))
    
    return confirmed_params

def main():
    global var, QUIET_MODE, MAX_RETRIES
    
    parser = argparse.ArgumentParser(
        description="ParamScout - Advanced HTTP Parameter Discovery Tool",
        epilog="Author: SYLHETYHACKVENGER (THE-ERROR808)"
    )
    parser.add_argument('-u', help='Target URL', dest='url')
    parser.add_argument('-o', '-oJ', help='Path for json output file.', dest='json_file')
    parser.add_argument('-oT', help='Path for text output file.', dest='text_file')
    parser.add_argument('-oB', help='Output to Burp Suite Proxy. Default is 127.0.0.1:8080.', dest='burp_proxy', nargs='?', const='127.0.0.1:8080')
    parser.add_argument('-d', help='Delay between requests in seconds. (default: 0)', dest='delay', type=float, default=0)
    parser.add_argument('-t', help='Number of concurrent threads. (default: 5)', dest='threads', type=int, default=5)
    parser.add_argument('-w', help='Wordlist file path. (default: assets/db/large.txt)', dest='wordlist', default='large')
    parser.add_argument('-m', help='Request method to use: GET/POST/XML/JSON. (default: GET)', dest='method', default='GET')
    parser.add_argument('-i', help='Import target URLs from file.', dest='import_file', nargs='?', const=True)
    parser.add_argument('-T', help='HTTP request timeout in seconds. (default: 15)', dest='timeout', type=float, default=15)
    parser.add_argument('-c', help='Chunk size. The number of parameters to be sent at once', type=int, dest='chunks', default=250)
    parser.add_argument('-q', help='Quiet mode. No output.', dest='quiet', action='store_true')
    parser.add_argument('--rate-limit', help='Max number of requests to be sent out per second (default: 9999)', dest='rate_limit', type=int, default=9999)
    parser.add_argument('--headers', help='Add headers. Separate multiple headers with a new line.', dest='headers', nargs='?', const=True)
    parser.add_argument('--passive', help='Collect parameter names from passive sources like wayback, commoncrawl and otx.', dest='passive', nargs='?', const='-')
    parser.add_argument('--stable', help='Prefer stability over speed.', dest='stable', action='store_true')
    parser.add_argument('--include', help='Include this data in every request.', dest='include', default='')
    parser.add_argument('--disable-redirects', help='disable redirects', dest='disable_redirects', action='store_true')
    parser.add_argument('--casing', help='casing style for params e.g. like_this, likeThis, likethis', dest='casing')
    parser.add_argument('--retries', help=argparse.SUPPRESS, type=int, default=3)
    parser.add_argument('--verify-ssl', help=argparse.SUPPRESS, action='store_true')
    parser.add_argument('--max-response-size', help=argparse.SUPPRESS, type=int, default=20_000_000)
    args = parser.parse_args()

    if args.quiet:
        QUIET_MODE = True

    show_banner()

    var = vars(args)
    var['method'] = var['method'].upper()
    MAX_RETRIES = args.retries

    if var['method'] != 'GET':
        var['chunks'] = 500

    if var['stable'] or var['delay']:
        var['threads'] = 1

    script_dir = os.path.dirname(os.path.abspath(__file__))
    db_dir = os.path.join(script_dir, 'assets', 'db')
    os.makedirs(db_dir, exist_ok=True)

    if var['wordlist'] in ('large', 'medium', 'small'):
        var['wordlist'] = os.path.join(db_dir, f'{var["wordlist"]}.txt')

    wordlist = []
    try:
        if var['wordlist'] and os.path.exists(var['wordlist']):
            wordlist = reader(var['wordlist'], mode='lines') or []
        else:
            default_wordlist = os.path.join(db_dir, 'large.txt')
            if os.path.exists(default_wordlist):
                wordlist = reader(default_wordlist, mode='lines') or []
            else:
                wordlist = ['id', 'page', 'sort', 'order', 'limit', 'offset', 'q', 'query']
                custom_print('%s Using built-in wordlist' % info)

        if var['passive']:
            host = var['passive']
            if host == '-' and args.url:
                host = urlparse(args.url).netloc
            if host:
                custom_print('%s Collecting parameter names from passive sources for %s, it may take a while' % (run, host))
                passive_params = fetch_params(host)
                if passive_params:
                    wordlist.extend(list(passive_params))
                    custom_print('%s Collected %s parameters, added to the wordlist' % (info, len(passive_params)))

        if args.casing and wordlist:
            delimiter, casing = detect_casing(args.casing)
            wordlist = [covert_to_case(str(word), delimiter, casing) for word in wordlist]

    except Exception as e:
        custom_print('%s Error loading wordlist: %s' % (bad, str(e)))
        if not wordlist:
            wordlist = ['id', 'page', 'sort', 'order', 'limit', 'offset', 'q', 'query']

    wordlist = list(set(filter(None, wordlist)))
    
    if not wordlist:
        wordlist = ['id', 'page', 'sort', 'order', 'limit', 'offset', 'q', 'query']
        custom_print('%s Using minimal default wordlist' % info)

    chunks = max(1, var.get('chunks', 250))
    if len(wordlist) < chunks:
        var['chunks'] = max(1, int(len(wordlist) / 2))

    if not args.url and not args.import_file:
        custom_print('%s No target(s) specified' % bad)
        custom_print('Usage: python3 paramscout.py -u "https://example.com"')
        sys.exit(1)

    requests_list = prepare_requests(args)

    if not requests_list:
        custom_print('%s No valid requests to process' % bad)
        sys.exit(1)

    final_result = {}
    is_single = False if args.import_file else True

    try:
        kill_event.clear()
        count = 0
        
        for request in requests_list:
            if kill_event.is_set():
                break
                
            url = request['url']
            custom_print('%s Scanning %d/%d: %s' % (run, count + 1, len(requests_list), url))
            
            these_params = initialize(request, wordlist, single_url=is_single)
            count += 1
            kill_event.clear()
            with LOCK:
                var['bad_req_count'] = 0
            
            if these_params == 'skipped':
                custom_print('%s Skipped %s due to errors' % (bad, url))
            elif these_params:
                final_result[url] = {
                    'params': these_params,
                    'method': request['method'],
                    'headers': request['headers']
                }
                exporter(final_result)
                custom_print('%s Parameters found: %s\n' % (good, ', '.join(these_params)))
                if not var['json_file']:
                    final_result = {}
            else:
                custom_print('%s No parameters were discovered.\n' % info)
                
    except KeyboardInterrupt:
        custom_print('\n%s Exiting...' % info)
        sys.exit(0)
    except Exception as e:
        custom_print('%s Error: %s' % (bad, str(e)))
        sys.exit(1)

if __name__ == '__main__':
    main()
