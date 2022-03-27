#!/usr/bin/python3
from __future__ import absolute_import
from datetime import datetime, timedelta
import json
import logging
import random

from base import WechatPayDALBase
import requests

pay_logger =  logging.getLogger('pay')


class WechatPayDAL(WechatPayDALBase):
    def get_official_cert(self):
        '''
        获取微信更新证书并保存
        '''
        url = 'https://api.mch.weixin.qq.com/v3/certificates'
        headers = self.make_headers_v3(url)
        rsp = requests.get(url, headers=headers)
        pay_logger.info('rsp:{}|{}'.format(rsp.status_code, rsp.content))
        rdct = rsp.json()
        for info in rdct['data']:
            ret = self.decrypt_v3(info)
            fpath = 'wechat_official_cert_{}.pem'.format(info['serial_no'])
            with open(fpath, 'wb') as ofile:
                ofile.write(ret)

        return fpath

    def create_order_info(self, data, callback_url):
        '''
        创建微信预支付订单, 注意包含两次签名过程:
        首次签名用于请求微信后端获取prepay_id
        二次签名信息返回客户端用于调起SDK支付
        '''
        url = 'https://api.mch.weixin.qq.com/v3/pay/transactions/app'
        ndt = datetime.now()
        out_trade_no = self.generate_partner_trade_no(ndt)
        data = {
            'mchid': self.mchid,
            'out_trade_no': out_trade_no,
            'appid': self.mch_appid,
            'description': data['subject'],
            'notify_url': callback_url,
            'amount': {
                'currency': 'CNY',
                'total': int(data['price']),
            },
            'time_expire': (ndt + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S+08:00')
        }
        jdata = json.dumps(data, separators=[',', ':'])
        headers = {'Content-Type': 'application/json'}
        # 第一次签名, 直接请求微信后端
        headers = self.make_headers_v3(url, headers=headers, body=jdata, method='POST')
        rsp = requests.post(url, headers=headers, data=jdata)
        pay_logger.info('rsp:{}|{}'.format(rsp.status_code, rsp.text))
        rdct = rsp.json()
        # 第二次签名, 返回给客户端调用
        sign_info = self.get_pay_sign_info(rdct['prepay_id'])
        return sign_info

    def query_order(self, out_trade_no):
        '''
        查询指定订单信息
        '''
        url = f'https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/{out_trade_no}?mchid={self.mchid}'
        headers = self.make_headers_v3(url)
        rsp = requests.get(url, headers=headers)
        pay_logger.info('out_trade_no:{}, rsp:{}|{}'.format(out_trade_no, rsp.status_code, rsp.text))
        rdct = rsp.json()
        return rdct
