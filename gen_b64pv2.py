# -*- coding: utf-8 -*-
import base64
old = """        function parseVerifyState(text) {
          const t = text || '';
          if (/无法|失败|未知|None|解析失败/.test(t)) {
            return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
          }
          if (t.includes('已吊销') || t.includes('已被')) {
            const m = t.match(/原因[:：]?\\s*(\\d+)/);
            const reason = m ? (V_REASONS[parseInt(m[1], 10)] || ('原因码 ' + m[1])) : '';
            return { k: 'revoked', badge: '已吊销', txt: reason ? '因' + reason + '，证书已被吊销' : '证书已被吊销' };
          }
          if (t.includes('证书正常') || t.includes('正常')) {
            return { k: 'ok', badge: '正常', txt: '证书有效，状态正常' };
          }
          return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
        }"""
new = """        function parseVerifyState(text) {
          const t = text || '';
          if (t.includes('已吊销') || t.includes('已被')) {
            const m = t.match(/原因[:：]?\\s*(\\d+)/);
            const reason = m ? (V_REASONS[parseInt(m[1], 10)] || ('原因码 ' + m[1])) : '';
            return { k: 'revoked', badge: '已吊销', txt: reason ? '因' + reason + '，证书已被吊销' : '证书已被吊销' };
          }
          const unknownPat = /无法获取|无法检查|获取失败|请求失败|解析失败|未找到|不存在|无签名响应|None/;
          if (unknownPat.test(t)) {
            return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
          }
          if (t.includes('证书正常') || t.includes('正常')) {
            return { k: 'ok', badge: '正常', txt: '证书有效，状态正常' };
          }
          return { k: 'unknown', badge: '未知', txt: '证书有效，因实时数据获取失败无法进行权威校验' };
        }"""
print('old=' + base64.b64encode(old.encode('utf-8')).decode())
print('NEW=' + base64.b64encode(new.encode('utf-8')).decode())
