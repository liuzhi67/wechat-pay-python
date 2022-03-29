#!/usr/bin/python3
from __future__ import absolute_import
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
import random
import time
from urllib3.util import parse_url


class WechatPayDALBase(object):
    def __init__(self, mch_appid, mchid, v3key, serial_no, client_key):
        self.mch_appid = mch_appid
        self.mchid = mchid
        self.v3key = v3key
        # serial_no可通过openssl直接获取, 例: openssl x509 -in 1900009191_20180326_cert.pem -noout -serial
        self.serial_no = serial_no

        with open(client_key, 'r') as ifile:
            pkey = RSA.importKey(ifile.read())
        self.signer = pkcs1_15.new(pkey)

    def compute_sign_v3(self, method, url, body):
        '''
        V3签名逻辑
        '''
        ts = int(time.time())
        nonce = self.generate_nonce()
        uparts= parse_url(url)
        ustr = uparts.path + ('?{}'.format(uparts.query) if uparts.query else '')
        content = '{}\n{}\n{}\n{}\n{}\n'.format(method, ustr, ts, nonce, body)

        digest = SHA256.new(content.encode('utf-8'))
        sign_v = base64.b64encode(self.signer.sign(digest)).decode('utf-8')
        sign_str = 'serial_no="{}",mchid="{}",timestamp="{}",nonce_str="{}",signature="{}"'.format(
                    self.serial_no, self.mchid, ts, nonce, sign_v)
        return sign_str

    def get_pay_sign_info(self, prepay_id):
        ts = int(time.time())
        nonce = self.generate_nonce()
        content = '{}\n{}\n{}\n{}\n'.format(self.mch_appid, ts, nonce, prepay_id)

        digest = SHA256.new(content.encode('utf-8'))
        sign_v = base64.b64encode(self.signer.sign(digest)).decode('utf-8')
        return {
            'appid': self.mch_appid,
            'partnerid': self.mchid,
            'timestamp': str(ts),
            'noncestr': nonce,
            'prepay_id': prepay_id,
            'package': 'Sign=WXPay',
            'sign': sign_v,
        }

    def decrypt_v3(self, dct):
        key_bytes = self.v3key.encode()
        nonce_bytes = dct['encrypt_certificate']['nonce'].encode()
        ad_bytes = dct['encrypt_certificate']['associated_data'].encode()
        data = base64.b64decode(dct['encrypt_certificate']['ciphertext'])

        aesgcm = AESGCM(key_bytes)
        ret = aesgcm.decrypt(nonce_bytes, data, ad_bytes)
        return ret

    def make_headers_v3(self, url, headers=None, body='', method='GET'):
        '''
        微信支付V3版本签名header生成函数
        '''
        if not headers:
            headers = {}
        headers['Accept'] = 'application/json'
        sign = self.compute_sign_v3(method, url, body)
        auth_info = 'WECHATPAY2-SHA256-RSA2048 {}'.format(sign)
        headers['Authorization'] = auth_info
        return headers

    def generate_nonce(self):
        rnd = int(time.time()) + random.randint(100000, 1000000)
        nonce = hashlib.md5(str(rnd).encode()).hexdigest()[:16]
        return nonce

    def generate_partner_trade_no(self, ndt):
        # 商户订单号必须保证唯一
        # 支付失败、异常一定要使用原订单号重试，更换订单号可能造成重复支付
        # 合理判断逻辑: 应先判断协议字段返回，再判断业务返回，最后判断交易状态
        rpart = random.randint(100000, 1000000)
        tid = '{}{}'.format(ndt.strftime('WX%Y%m%d%H%M%S%f'), rpart)
        return tid
