import requests, random, threading, logging, colorlog, os, json, re, base64, threading, queue, time, uuid, jwt, datetime, string
from urllib.parse import unquote
from bs4 import BeautifulSoup
#from curl_cffi import requests


path_to_json = os.path.abspath('./config')
file_path = os.path.join(path_to_json, "config.json")
with open(file_path, 'r') as file:
    config = json.load(file)
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
))

logger = colorlog.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

working_proxies = []
error = None

def proxy_appender(proxy_url: str, proxy_protocol: str) -> None:
    global error

    proxies = None

    if proxy_protocol == 'HTTP':
        proxies = {
            'http': f"http://{proxy_url}",
            'https': f"http://{proxy_url}"
        }
    elif proxy_protocol == 'SOCKS4':
        proxies = {
            'http': f"socks4://{proxy_url}",
            'https': f"socks4://{proxy_url}"
        }
    elif proxy_protocol == 'SOCKS5':
        proxies = {
            'http': f"socks5://{proxy_url}",
            'https': f"socks5://{proxy_url}"
        }

    else:
        error = 'Invalid proxy protocol.'

    try:
        a = requests.get("http://ip-api.com/json/", proxies=proxies, timeout=10, verify=False)
        working_proxies.append(proxies["http"].split("//")[1])
    except:
        pass


class proxy_checker:
    def __init__(self, config):
        self.config = config

    def check_proxies(self) -> list:
        global error, working_proxies

        with open(f'./config/proxies.txt') as file:
            proxies = [line.rstrip() for line in file.readlines()]
    

        threads = []
        for proxy_url in proxies:
            t = threading.Thread(target=proxy_appender, args=(proxy_url, self.config["PROXY_TYPE"],))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if error:
            return [False, error]

        if len(working_proxies) == 0:
            return [False, 'Proxies not working. Please fill proxies.txt with new proxies.']

        return [True, working_proxies, len(working_proxies)]
    

class user_data:
    def __init__(self) -> None:
        pass

    def get_user(self, locale, gender):
        res = requests.get(f"https://fakerapi.it/api/v1/users?_quantity=1&_locale={locale}&_gender={gender}").json()
        if res["status"] == "OK":
            return res["data"][0]

    def get_useragent(self):
        try:
            res = requests.get("https://fingerprints.bablosoft.com/preview?rand=0.1&tags=iPhone").json()
            return res["ua"]
        except:
            None


def random_uuid():
    return str(uuid.uuid4())


def random_timestamp():
    start = datetime(2020, 1, 1)
    end = datetime.now()
    random_time = start + (end - start) * random.random()
    return random_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def random_ga():
    ga_id = random.randint(1000000000, 9999999999)
    timestamp = int(time.time())
    return f"GA1.1.{ga_id}.{timestamp}"

def generate_random_secret(length=32):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def generate_random_user_id():
    return random.randint(1, 1000)


def create_jwt(id):
    secret_key = generate_random_secret()
    user_id = id
    payload = {
        "id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
        "iat": datetime.datetime.utcnow(),
        "iss": "suamusica.com.br",
        "sub": "suamusica.com.br"
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token


class API:
    def __init__(self, proxies = None) -> None:
        self.proxies = proxies
        self.session = requests.Session()
        stop = True
        while stop:
            usg = user_data().get_useragent()
            if usg is not None:
                self.useragent = usg
                stop = False
        print(usg)
        #self.session.impersonate = "safari17_2_ios"     
        
        #self.session.proxies.update({"http": f"http://23704217-zone-custom-region-BR:UpQ1JgNf@f.proxys5.net:6200", "https": f"http://23704217-zone-custom-region-BR:UpQ1JgNf@f.proxys5.net:6200"})
        if self.proxies:      
            logger.info(f"Proxy Using: {self.proxies}")
            if config["PROXY"]["PROXY_USAGE"] == "HTTP":
                self.session.proxies.update({"http": f"http://{random.choice(proxies)}", "https": f"http://{random.choice(proxies)}"})
            elif  config["PROXY"]["PROXY_USAGE"] == "SOCKS4":
                self.session.proxies.update({"http": f"socks4://{random.choice(proxies)}", "https": f"socks4://{random.choice(proxies)}"})
            elif  config["PROXY"]["PROXY_USAGE"] == "SOCKS5":
                self.session.proxies.update({"http": f"socks5://{random.choice(proxies)}", "socks5": f"socks4://{random.choice(proxies)}"})


        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-GB,en;q=0.9',
            'priority': 'u=0, i',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': self.useragent
        }

        self.session.headers.update(headers)

    def send_stream(self):
        response = self.session.get(config["STREAM_SETTINGS"]["STREAM_LINK"])
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tag = soup.find('script', id='__NEXT_DATA__', type='application/json')

        if script_tag:
            script_content = script_tag.string
            
            try:
                data = json.loads(script_content)
                album_info = data["props"]["pageProps"]["album"]
                logger.info(f"Album_id: {album_info['id']} Name: {album_info['name']} Title: {album_info['title']}")
                self.albumid = album_info["id"]
                self.arqId = album_info["files"][0]["id"]
            except json.JSONDecodeError:
                print("JSON ayrıştırma hatası.")
        else:
            print("Script etiketi bulunamadı.")

        app_script = None
        for script in soup.find_all('script', src=True):
            if '/_next/static/chunks/pages/_app-' in script['src']:
                app_script = script['src']
                break

        if app_script:
            logger.debug(f"App script src: {app_script}")
        else:
            logger.debug("App script src cant find.")

        response = self.session.get(f"https://suamusica.com.br/{app_script}")
        
        match = re.search(r'spotId:\s*"([^"]+)"', response.text)

        if match:
            spot_id = match.group(1)
            self.spot_id = spot_id
            logger.debug(f"Spot ID: {spot_id}")
        else:
            logger.debug("Spot ID cant find")

        app_id_match = re.search(r'appId:\s*"([^"]+)"', response.text)
        if app_id_match:
            app_id = app_id_match.group(1)
            logger.debug(f"appId: {app_id}")
        else:
            logger.debug("appId cant find.")

        self.authVersion = "FIS_v2"
        self.sdkVersion = "w:0.6.4"
        self.app_id = app_id
        self.fid = "ejNpABJcyHtabZQDvSgwGr"

        data = {
            "fid": self.fid,
            "authVersion": self.authVersion,
            "appId": self.app_id,
            "sdkVersion": self.authVersion
        }

        response = self.session.get("https://api-2-0.spot.im/v1.0.0/device-load")
        logger.debug(f"Device id: {response.text}")
        self.device_id = response.text
        self.session.cookies.update(response.cookies)

        headers = {
            'accept': '*/*',
            'accept-language': 'en-GB,en;q=0.9',
            'content-length': '0',
            'content-type': 'application/json',
            'origin': 'https://suamusica.com.br',
            'priority': 'u=1, i',
            'referer': 'https://suamusica.com.br/',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'cross-site',
            'user-agent': self.useragent,
            'x-post-id': 'no$post',
            'x-spot-id': spot_id,
            'x-spotim-device-uuid': self.device_id
        }
        
        response = self.session.post("https://api-2-0.spot.im/v1.0.0/authenticate", headers=headers)
        logger.info(response.text)
        self.session.cookies.update(response.cookies)
        token = self.session.cookies.get("access_token")
        logger.info(f"Access Token: {token}")
        

        first_event_id = random_uuid()
        session_id = random_uuid()
        user_id = random_uuid()
        id_ = random_uuid()
        id__ = random_uuid()
        ga_ = random_ga()
        eid = random_uuid()

        """
        b64_p = {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
                {
                "schema": "iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0",
                "data": {
                    "name": "CD",
                    "id": id_
                }
                },
                {
                "schema": "iglu:com.google.analytics/cookies/jsonschema/1-0-0",
                "data": {
                    "_ga": ga_
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/web_page/jsonschema/1-0-0",
                "data": {
                    "id": id__
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/client_session/jsonschema/1-0-2",
                "data": {
                    "userId": user_id,
                    "sessionId": session_id,
                    "eventIndex": 1,
                    "sessionIndex": 1,
                    "previousSessionId": None,
                    "storageMechanism": "COOKIE_1",
                    "firstEventId": first_event_id,
                    "firstEventTimestamp": "2024-06-29T22:18:48.783Z"
                }
                }
            ]
        }
        
        text_bytes = str(b64_p).encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        token_base64 = base64_bytes.decode('utf-8')
        
        data = {
            "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
            "data": [
                {
                    "e": "pv",
                    "url": "https://suamusica.com.br/roccaa",
                    "page": "rocca - Pagode - Sua Música - Sua Música",
                    "eid": first_event_id,
                    "tv": "js-3.23.1",
                    "tna": "newsm",
                    "p": "web",
                    "cookie": "1",
                    "cs": "UTF-8",
                    "lang": "en-GB",
                    "res": "1920x1080",
                    "cd": "24",
                    "dtm": "1719699528783",
                    "cx": token_base64,
                    "vp": "415x958",
                    "ds": "415x958",
                    "vid": "1",
                    "sid": session_id,
                    "duid": user_id,
                    "stm": "1719699528787"
                }
            ]
        }


        response = self.session.post("https://snowplow.suamusica.com.br/com.snowplowanalytics.snowplow/tp2", json=data)
        logger.info(f"Starting song: {config['STREAM_SETTINGS']['STREAM_LINK']} Device_id: {self.device_id} Response: {response.text}")
        self.session.cookies.update(response.cookies)


        b64_p = {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
                {
                "schema": "iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0",
                "data": {
                    "name": "CD",
                    "id": id_
                }
                },
                {
                "schema": "iglu:com.google.analytics/cookies/jsonschema/1-0-0",
                "data": {
                    "_ga": ga_
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/web_page/jsonschema/1-0-0",
                "data": {
                    "id": id__
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/client_session/jsonschema/1-0-2",
                "data": {
                    "userId": user_id,
                    "sessionId": session_id,
                    "eventIndex": 3,
                    "sessionIndex": 1,
                    "previousSessionId": None,
                    "storageMechanism": "COOKIE_1",
                    "firstEventId": first_event_id,
                    "firstEventTimestamp": "2024-06-29T22:18:48.783Z"
                }
                }
            ]
        }
        
        text_bytes = str(b64_p).encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        token_base64 = base64_bytes.decode('utf-8')
        
        data = {
            "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
            "data": [
                {
                    "e": "se",
                    "se_ca": "Preload",
                    "se_ac": "PageView",
                    "se_la": "João Gomes",
                    "se_va": "4414373",
                    "eid": eid,
                    "tv": "js-3.23.1",
                    "tna": "newsm",
                    "p": "web",
                    "cookie": "1",
                    "cs": "UTF-8",
                    "lang": "en-GB",
                    "res": "1920x1080",
                    "cd": "24",
                    "dtm": "1719699532371",
                    "vp": "415x958",
                    "ds": "425x1288",
                    "vid": "1",
                    "sid": session_id,
                    "duid": user_id,
                    "url": "https://suamusica.com.br/roccaa",
                    "cx": token_base64,
                    "stm": "1719699532372"
                }
            ]
        }
    
        response = self.session.post("https://snowplow.suamusica.com.br/com.snowplowanalytics.snowplow/tp2", json=data)
        logger.info(f"Page Load: {config['STREAM_SETTINGS']['STREAM_LINK']} Device_id: {self.device_id} Response: {response.text}")
        self.session.cookies.update(response.cookies)


        b64_p = {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
                {
                "schema": "iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0",
                "data": {
                    "name": "CD",
                    "id": id_
                }
                },
                {
                "schema": "iglu:com.google.analytics/cookies/jsonschema/1-0-0",
                "data": {
                    "_ga": ga_
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/web_page/jsonschema/1-0-0",
                "data": {
                    "id": id__
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/client_session/jsonschema/1-0-2",
                "data": {
                    "userId": user_id,
                    "sessionId": session_id,
                    "eventIndex": 4,
                    "sessionIndex": 1,
                    "previousSessionId": None,
                    "storageMechanism": "COOKIE_1",
                    "firstEventId": first_event_id,
                    "firstEventTimestamp": "2024-06-29T22:18:48.783Z"
                }
                }
            ]
        }
        
        text_bytes = str(b64_p).encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        token_base64 = base64_bytes.decode('utf-8')
        
        data = {
            "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
            "data": [
                {
                    "e": "se",
                    "se_ca": "/roccaa",
                    "se_ac": "CD",
                    "se_la": "rocca",
                    "se_va": "4416697",
                    "eid": eid,
                    "tv": "js-3.23.1",
                    "tna": "newsm",
                    "p": "web",
                    "cookie": "1",
                    "cs": "UTF-8",
                    "lang": "en-GB",
                    "res": "1920x1080",
                    "cd": "24",
                    "dtm": "1719699544657",
                    "vp": "415x958",
                    "ds": "425x2119",
                    "vid": "1",
                    "sid": session_id,
                    "duid": user_id,
                    "url": "https://suamusica.com.br/roccaa",
                    "cx": token_base64,
                    "stm": "1719699544658"
                }
            ]
        }
    
        response = self.session.post("https://snowplow.suamusica.com.br/com.snowplowanalytics.snowplow/tp2", json=data)
        logger.info(f"Song Loading: {config['STREAM_SETTINGS']['STREAM_LINK']} Device_id: {self.device_id} Response: {response.text}")
        self.session.cookies.update(response.cookies)

        b64_p = {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
                {
                "schema": "iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0",
                "data": {
                    "name": "CD",
                    "id": id_
                }
                },
                {
                "schema": "iglu:com.google.analytics/cookies/jsonschema/1-0-0",
                "data": {
                    "_ga": ga_
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/web_page/jsonschema/1-0-0",
                "data": {
                    "id": id__
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/client_session/jsonschema/1-0-2",
                "data": {
                    "userId": user_id,
                    "sessionId": session_id,
                    "eventIndex": 5,
                    "sessionIndex": 1,
                    "previousSessionId": None,
                    "storageMechanism": "COOKIE_1",
                    "firstEventId": first_event_id,
                    "firstEventTimestamp": "2024-06-29T22:18:48.783Z"
                }
                }
            ]
        }
        
        text_bytes = str(b64_p).encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        token_base64 = base64_bytes.decode('utf-8')
        
        data = {
            "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
            "data": [
                {
                    "e": "se",
                    "se_ca": "Player Aberto",
                    "se_ac": "Controles",
                    "se_la": "Loading",
                    "eid": eid,
                    "tv": "js-3.23.1",
                    "tna": "newsm",
                    "p": "web",
                    "cookie": "1",
                    "cs": "UTF-8",
                    "lang": "en-GB",
                    "res": "1920x1080",
                    "cd": "24",
                    "dtm": "1719699544753",
                    "vp": "415x958",
                    "ds": "425x2119",
                    "vid": "1",
                    "sid": session_id,
                    "duid": user_id,
                    "url": "https://suamusica.com.br/roccaa",
                    "cx": token_base64,
                    "stm": "1719699544871"
                }
            ]
        }
    
        response = self.session.post("https://snowplow.suamusica.com.br/com.snowplowanalytics.snowplow/tp2", json=data)
        logger.info(f"Song Loading: {config['STREAM_SETTINGS']['STREAM_LINK']} Device_id: {self.device_id} Response: {response.text}")
        self.session.cookies.update(response.cookies)

        b64_p = {
            "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-0",
            "data": [
                {
                "schema": "iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0",
                "data": {
                    "name": "CD",
                    "id": id_
                }
                },
                {
                "schema": "iglu:com.google.analytics/cookies/jsonschema/1-0-0",
                "data": {
                    "_ga": ga_
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/web_page/jsonschema/1-0-0",
                "data": {
                    "id": id__
                }
                },
                {
                "schema": "iglu:com.snowplowanalytics.snowplow/client_session/jsonschema/1-0-2",
                "data": {
                    "userId": user_id,
                    "sessionId": session_id,
                    "eventIndex": 6,
                    "sessionIndex": 1,
                    "previousSessionId": None,
                    "storageMechanism": "COOKIE_1",
                    "firstEventId": first_event_id,
                    "firstEventTimestamp": "2024-06-29T22:18:48.783Z"
                }
                }
            ]
        }
        
        text_bytes = str(b64_p).encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        token_base64 = base64_bytes.decode('utf-8')
        
        data = {
            "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
            "data": [
                {
                    "e": "se",
                    "se_ca": "Player Aberto",
                    "se_ac": "Controles",
                    "se_la": "Play",
                    "eid": eid,
                    "tv": "js-3.23.1",
                    "tna": "newsm",
                    "p": "web",
                    "cookie": "1",
                    "cs": "UTF-8",
                    "lang": "en-GB",
                    "res": "1920x1080",
                    "cd": "24",
                    "dtm": "1719699548246",
                    "vp": "415x958",
                    "ds": "425x2119",
                    "vid": "1",
                    "sid": session_id,
                    "duid": user_id,
                    "url": "https://suamusica.com.br/roccaa",
                    "cx": token_base64,
                    "stm": "1719699548247"
                }
            ]
        }
    
        response = self.session.post("https://snowplow.suamusica.com.br/com.snowplowanalytics.snowplow/tp2", json=data)
        logger.info(f"Song Playing: {config['STREAM_SETTINGS']['STREAM_LINK']} Device_id: {self.device_id} Response: {response.text}")
        self.session.cookies.update(response.cookies)        

        """
        play_token = f'{{"albumId":{self.albumid},"arqId":{self.arqId},"playlistId":0,"gaid":"{ga_}","newgaid":45874431454777{random.randint(10,90)}}}'
        text_bytes = play_token.encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        playtoken_base64 = base64_bytes.decode('utf-8')
        logger.info(f"Play Token: {playtoken_base64}")

        token = create_jwt(user_id)
        #token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYxMzMwOTc4IiwiZXhwIjoxNzIwMzgwMjI5LCJpYXQiOjE3MTk3NzU0MjksImlzcyI6InN1YW11c2ljYS5jb20uYnIiLCJzdWIiOiJzdWFtdXNpY2EuY29tLmJyIn0.GKQ5HaREmPuFCy04J2SaFU4KmFYGX0R66epjnVfttVw"
        data = {
            "params": playtoken_base64
        }

        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-GB,en;q=0.9',
            'access-control-allow-origin': '*',
            'appplatform': 'web',
            'appversioncode': '1005',
            'authorization': f'Bearer {token}',
            'content-type': 'application/json',
            'cookie': '; '.join([f'{name}={value}' for name, value in self.session.cookies.items()]),
            'origin': 'https://suamusica.com.br',
            'priority': 'u=1, i',
            'referer': 'https://suamusica.com.br/bebedaniel/senorita',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.useragent
        }

        response = self.session.post("https://suamusica.com.br/api/play", headers=headers, json=data)
        logger.info(response.text)
        if "200" in response.text:
            self.session.cookies.update(response.cookies)
            logger.info(f"Stream Sent to {config['STREAM_SETTINGS']['STREAM_LINK']} Response: {response.text}")

            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-GB,en;q=0.9',
                'access-control-allow-origin': '*',
                'appplatform': 'web',
                'appversioncode': '1005',
                'authorization': f'Bearer {token}',
                'content-type': 'application/json',
                'cookie': '; '.join([f'{name}={value}' for name, value in self.session.cookies.items()]),
                'origin': 'https://suamusica.com.br',
                'priority': 'u=1, i',
                'referer': 'https://suamusica.com.br/roccaa',
                'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': self.useragent
            }

            data = {
                "params": playtoken_base64
            }

            response = self.session.post("https://suamusica.com.br/api/download", headers=headers, json=data)
            logger.info(f"Song Downloaded: {config['STREAM_SETTINGS']['STREAM_LINK']} Response: {response.text}")
            return True
        else:
            logger.error(f"Stream Cant Sent {config['STREAM_SETTINGS']['STREAM_LINK']} Response: {response.text}")
            return False


class Worker(threading.Thread):
    def __init__(self, task_queue, result_queue):
        threading.Thread.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        while True:
            task = self.task_queue.get()
            if task is None:
                self.task_queue.task_done()
                break

            api = API()
            success = False
            while not success:
                success = api.send_stream()
                if success:
                    self.result_queue.put('success')
                else:
                    self.result_queue.put('fail')
            self.task_queue.task_done()

def main():
    stream_count = config["STREAM_SETTINGS"]["STREAM_AMOUNT"]
    fail_stream_count = 0

    task_queue = queue.Queue()
    result_queue = queue.Queue()


    num_worker_threads = 10
    threads = []
    for _ in range(num_worker_threads):
        worker = Worker(task_queue, result_queue)
        worker.start()
        threads.append(worker)


    for _ in range(stream_count):
        task_queue.put('send_stream')


    for _ in range(num_worker_threads):
        task_queue.put(None)


    while any(t.is_alive() for t in threads) or not result_queue.empty():
        try:
            result = result_queue.get(timeout=0.1)
            if result == 'success':
                stream_count += 1
            elif result == 'fail':
                fail_stream_count += 1
        except queue.Empty:
            pass


    for t in threads:
        t.join()


    print(f"Stream Count: {stream_count}")
    print(f"Fail Stream Count: {fail_stream_count}")

if __name__ == "__main__":
    main()

