<!-- @NOCOMPRESS -->
## `1`规范说明
***************

### `1.1`通信协议
HTTPS 协议。

### `1.2`请求方法
易盾反垃圾云服务提供的所有接口，均支持 POST/GET 方法。当参数名与参数值拼装起来的 URL 长度小于 1024 个字符时，可以用GET发起请求；当参数类型含 byte[] 类型或拼装好的请求URL过长时，必须用 POST 发起请求。建议所有API调用都使用 POST 方法请求。

### `1.3`字符编码
所有接口的请求和响应数据编码皆为 utf-8。

### `1.4`API请求结构
| 名称 | 描述 | 备注 |
|------|------|------|
| API入口 | 具体API接口地址 | 如 `https://api.aq.163.com/vx/xx/check` |
| 公共参数 | 每个接口都包含的通用参数 | 详见 [公共参数](#2) 说明 |
| 私有参数 | 每个接口特有的参数 | 详见每个API接口定义 |

## `2`公共参数
**************
公共参数是用于标识产品和接口鉴权目的的参数，如非必要，在每个接口单独的接口文档中不再对这些参数进行说明，每次请求均需要携带这些参数。

### `2.1`请求公共参数

| 参数名称 | 类型 | 是否必选 | 最大长度| 描述 |
|----------|------|------|------|-----|
| secretId | String | Y | 32 |产品秘钥 id ，由易盾反垃圾云服务分配，产品标识 |
| businessId | String| Y | 32 |业务id ，由易盾反垃圾云服务分配，业务标识 |
| version | String| Y |4 |接口版本号，可选值 v2 |
| timestamp | Number | Y | 13 |请求当前 UNIX 时间戳，请注意服务器时间是否同步 |
| nonce | Number | Y | 11 |随机正整数，与 timestamp 联合起来，用于防止重放攻击 |
| signature | String| Y | 32 |请求签名，用来验证此次请求的合法性，具体算法见 [接口鉴权](#4) |

### `2.2`响应通用字段
所有接口响应值采用 json 格式， 如无特殊说明，每次请求的返回值中，都包含下面字段：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| code | Number | 接口调用状态，200:正常，其他值：调用出错，返回码见 [响应返回码](#3) |
| msg | String | 结果说明，如果接口调用出错，那么返回错误描述，成功返回 ok |
| result | String | 接口返回结果，各个接口自定义 |


## `3`响应返回码
***************

响应返回码（code）反应了易盾反垃圾云服务 API 调用和执行的概要结果。当返回码不为 200 时， 表示请求未正常执行，返回码描述 (msg) 对该结果进行了细化补充，用户可根据返回码判断 API 的执行情况。

所有接口调用返回值均包含 code 和 msg 字段， code 为返回码值，msg 为返回码描述信息，返回码表如下：

| 返回码 | 返回码描述 | 说明             |
|--------|------------|------------------|
| 200    | ok | 接口调用成功  |
| 400    | bad request | 请求缺少 secretId 或 businessId |
| 401    | forbidden   | secretId 或 businessId 错误 |
| 402    | business offline  |  业务未上线 |
| 404    | not found  | 业务配置不存在 |
| 405    | param error | 请求参数异常 |
| 410    | signature failure |  签名验证失败 |
| 411    | high frequency | 请求频率或数量超过限制 |
| 414    | param len over limit | 请求长度超过限制 |
| 420    | request expired | 请求过期 |
| 430    | replay attack  | 重放攻击 |
| 503    | service unavailable | 接口异常 |


## `4`接口鉴权
*****************

易盾反垃圾云服务使用签名方法对接口进行鉴权，所有接口每一次请求都需要包含签名信息（signature 参数），以验证用户身份，防止信息被恶意篡改。

### `4.1`申请安全凭证

在第一次使用 API 之前，需申请安全凭证，安全凭证包括 SecretId 和 SecretKey ，SecretId 是用于标识 API 调用者的身份，SecretKey 是用于加密签名字符串和服务器端验证签名字符串的密钥。SecretKey 必须严格保管，避免泄露。

### `4.2`签名生成算法

签名生成方法如下：

- 对所有请求参数（包括公有参数和私有参数，但不包括 signature 参数），按照参数名ASCII码表升序顺序排序。如：foo=1， bar=2， foo_bar=3， baz=4 排序后的顺序是 bar=2， baz=4， foo=1， foobar=3 。

- 将排序好的参数名和参数值构造成字符串，格式为：key1+value1+key2+value2… 。根据上面的示例得到的构造结果为：bar2baz4foo1foobar3 。

- 选择与 secretId 配对的 secretKey ，加到上一步构造好的参数字符串之后，如 secretKey=6308afb129ea00301bd7c79621d07591 ，则最后的参数字符串为 bar2baz4foo1foobar36308afb129ea00301bd7c79621d07591 。

- 把c步骤拼装好的字符串采用 utf-8 编码，使用 MD5 算法对字符串进行摘要，计算得到 signature 参数值，将其加入到接口请求参数中即可。MD5 是128位长度的摘要算法，用16进制表示，一个十六进制的字符能表示4个位，所以签名后的字符串长度固定为32位十六进制字符。

签名生成示例代码：

```java
/**
 * 生成签名信息
 * @param secretKey 产品私钥
 * @param params 接口请求参数名和参数值map，不包括signature参数名
 * @return
 */
public static String genSignature(String secretKey, Map<String, String> params){
    // 1. 参数名按照ASCII码表升序排序
    String[] keys = params.keySet().toArray(new String[0]);
    Arrays.sort(keys);

    // 2. 按照排序拼接参数名与参数值
    StringBuffer paramBuffer = new StringBuffer();
    for (String key : keys) {
        paramBuffer.append(key).append(params.get(key));
    }
    // 3. 将secretKey拼接到最后
    paramBuffer.append(secretKey);

    // 4. MD5是128位长度的摘要算法，用16进制表示，一个十六进制的字符能表示4个位，所以签名后的字符串长度固定为32个十六进制字符。
    return DigestUtils.md5Hex(paramBuffer.toString().getBytes("UTF-8"));
}
```

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""生成签名信息
Args:
    secretKey 产品私钥
    params 接口请求参数，不包括signature参数
"""
def gen_signature(secretKey, params=None):
        params_str = ""
        for k in sorted(params.keys()):
            params_str += str(k)+ str(params[k])

        params_str += secretKey
        return hashlib.md5(params_str).hexdigest()
```

```php
/**
 * 生成签名信息
 * $secretKey 产品私钥
 * $params 接口请求参数，不包括signature参数
 */
function gen_signature($secretKey,$params){
	ksort($params);
	$buff="";
	foreach($params as $key=>$value){
		$buff .=$key;
		$buff .=$value;
	}
	$buff .= $secretKey;
	return md5(mb_convert_encoding($buff, "utf8", "auto"));
}
```

```C#
// 根据secretKey和parameters生成签名
public static String genSignature(String secretKey, Dictionary<String, String> parameters)
{
    parameters = parameters.OrderBy(o => o.Key).ToDictionary(o => o.Key, p => p.Value);

    StringBuilder builder = new StringBuilder();
    foreach (KeyValuePair<String, String> kv in parameters)
    {
        builder.Append(kv.Key).Append(kv.Value);
    }
    builder.Append(secretKey);
    String tmp = builder.ToString();
    MD5 md5 = new MD5CryptoServiceProvider();
    byte[] result = md5.ComputeHash(Encoding.UTF8.GetBytes(tmp));
    builder.Clear();
    foreach (byte b in result)
    {
        builder.Append(b.ToString("x2").ToLower());
    }
    return builder.ToString();
}
```

```javascript
var genSignature=function(secretKey,paramsJson){
    var sorter=function(paramsJson){
        var sortedJson={};
        var sortedKeys=Object.keys(paramsJson).sort();
        for(var i=0;i&lt;sortedKeys.length;i++){
            sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
        }
        return sortedJson;
    }
    var sortedParam=sorter(paramsJson);
    var needSignatureStr="";
    needSignatureStr=paramsSortedString.replace(/&&/g,"");
    md5er.update(needSignatureStr,"UTF-8");
    return md5er.digest('hex');
};
```

## `5`接口调用流程
****************
易盾反垃圾云服务对外提供在线实时检测和离线检测结果获取两类接口。

- 在线实时检测接口是易盾反垃圾云服务实时反垃圾引擎检测接口，该接口实时返回检测结果，产品可以根据该结果对数据进行初步过滤。

- 离线检测结果获取接口返回易盾反垃圾云服务离线反垃圾引擎检测结果及部分人工质检结果，产品可根据该结果做进一步数据过滤。

以下是易盾反垃圾云服务接口调用示意图：

![易盾反垃圾云服务接口调用示意图](http://dun.163.com/res/yidun-api-flow.png)

## `6`文本在线检测
********************

### `6.1`接口地址
[https://api.aq.163.com/v2/text/check](https://api.aq.163.com/v2/text/check)

### `6.2`接口描述
根据发布的内容、发布者、ip、设备id等信息来检测是否为需拦截内容。接口同步返回易盾反垃圾云服务实时反垃圾引擎检测结果，产品可以根据该结果对数据进行初步过滤。该接口返回结果状态分以下三种：

- 不通过：表示是确认内容非法，产品可对数据做删除隐藏处理。

- 嫌疑：表示该内容疑似非法，需易盾反垃圾云服务离线检测模块进一步确认处理，确认结果需产品自行定期调用[文本离线检测结果获取](#7)获取，产品对嫌疑数据可以做特殊策略处理，如本人可见等。

- 通过：表示易盾反垃圾云服务实时反垃圾引擎未识别为非法内容，产品对该类数据可以直接放过，发表成功。易盾反垃圾云服务离线检测模块也会对这些数据做进一步分析处理，分析结果需产品自行定期调用[文本离线检测结果获取](#7)获取。

### `6.3`请求参数
公共参数已省略，详细见 [请求公共参数](#2_1)，其他参数如下：

| 参数名称  |  类型 | 是否必选 | 最大长度 | 描述 |
|-----------|-------|------|------|-------|
| dataId | String | Y | 128 |数据 id，唯一标识 |
| content | String | Y | 2^24-1 |用户发表内容，建议对内容中JSON、表情符、HTML标签、UBB标签等做过滤，只传递纯文本，以减少误判概率 |
| dataOpType | Number| Y | 4 |数据状态，1：新增， 3：修改 |
| ip | String | N | 32 |用户IP地址 |
| account | String | N | 128 |用户唯一标识，如果无需登录则为空 |
| deviceType |Number| N | 4 |用户设备类型，<br>1：web， 2：wap， 3：android， 4：iphone， 5：ipad， 6：pc， 7：wp |
| deviceId | String | N | 128 |用户设备 id |
| callback | String | N | 2^16-1 |数据回调参数，产品根据业务情况自行设计，当获取异步离线检测结果时，易盾反垃圾云服务会返回该字段，详细见[文本离线检测结果获取](#7) |
| publishTime | Number | N | 13 |发表时间，UNIX 时间戳(毫秒值) |


### `6.4`响应结果
响应字段如下，响应通用字段已省略，详细见[响应通用字段](#2_2)：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| result | json  |  result 包含二个字段：<br> action ：检测结果，1通过，2不通过，3嫌疑 <br>hitType：命中规则类型 |

### `6.5`请求示例
```java
/** 产品密钥ID，产品标识 */
String secretId="your_secret_id";
 /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
String secretKey="your_secret_key";
/** 业务ID，易盾根据产品业务特点分配 */
String businessId="your_business_id";
/** 易盾反垃圾云服务文本在线检测接口地址 */
String apiUrl="https://api.aq.163.com/v2/text/check";
/** 实例化HttpClient，发送http请求使用，可根据需要自行调参 */
HttpClient httpClient = HttpClient4Utils.createHttpClient(100, 20, 1000, 1000, 1000);
Map<String, String> params = new HashMap<String, String>();

// 1.设置公共参数
params.put("secretId", secretId);
params.put("businessId", businessId);
params.put("version", "v2");
params.put("timestamp", String.valueOf(System.currentTimeMillis()));
params.put("nonce", String.valueOf(new Random().nextInt()));

// 2.设置私有参数
params.put("dataId", "ebfcad1c-dba1-490c-b4de-e784c2691768");
params.put("content", "易盾测试内容！");
params.put("dataOpType", "1");
params.put("ip", "123.115.77.137");
params.put("account", "java@163.com");
params.put("deviceType", "4");
params.put("deviceId", "92B1E5AA-4C3D-4565-A8C2-86E297055088");
params.put("callback", "ebfcad1c-dba1-490c-b4de-e784c2691768");
params.put("publishTime", String.valueOf(System.currentTimeMillis()));

// 3.生成签名信息
String signature = SignatureUtils.genSignature(secretKey, params);
params.put("signature", signature);

// 4.发送HTTP请求，这里使用的是HttpClient工具包，产品可自行选择自己熟悉的工具包发送请求
String response = HttpClient4Utils.sendPost(httpClient, apiUrl, params, Consts.UTF_8);

// 5.解析接口返回值
JsonObject jObject = new JsonParser().parse(response).getAsJsonObject();
int code = jObject.get("code").getAsInt();
String msg = jObject.get("msg").getAsString();

if (code == 200) {
    JsonObject resultObject = jObject.getAsJsonObject("result");
    int action = resultObject.get("action").getAsInt();
    if (action == 1) {
      System.out.println("正常内容，通过");
    } else if (action == 2) {
      System.out.println("垃圾内容，删除");
    } else if (action == 3) {
      System.out.println("嫌疑内容");
    }
} else {
    System.out.println(String.format("ERROR: code=%s, msg=%s", code, msg));
}

```

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""易盾文本在线检测接口python示例代码
接口文档: http://dun.163.com/api.html
python版本：python2.7
运行:
    1. 修改 SECRET_ID,SECRET_KEY,BUSINESS_ID 为对应申请到的值
    2. $ python text_check_api_demo.py
"""
__author__ = 'yidun-dev'
__date__ = '2016/3/10'
__version__ = '0.1-dev'

import hashlib
import time
import random
import urllib
import urllib2
import json

class TextCheckAPIDemo(object):
    """文本在线检测接口示例代码"""
    API_URL = "https://api.aq.163.com/v2/text/check"
    VERSION = "v2"

    def __init__(self, secret_id, secret_key, business_id):
        """
        Args:
            secret_id (str) 产品密钥ID，产品标识
            secret_key (str) 产品私有密钥，服务端生成签名信息使用
            business_id (str) 业务ID，易盾根据产品业务特点分配
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.business_id = business_id

    def gen_signature(self, params=None):
        """生成签名信息
        Args:
            params (object) 请求参数
        Returns:
            参数签名md5值
        """
        buff = ""
        for k in sorted(params.keys()):
            buff += str(k)+ str(params[k])
        buff += self.secret_key
        return hashlib.md5(buff).hexdigest()

    def check(self, params):
        """请求易盾接口
        Args:
            params (object) 请求参数
        Returns:
            请求结果，json格式
        """
        params["secretId"] = self.secret_id
        params["businessId"] = self.business_id
        params["version"] = self.VERSION
        params["timestamp"] = int(time.time() * 1000)
        params["nonce"] = int(random.random()*100000000)
        params["signature"] = self.gen_signature(params)

        try:
            params = urllib.urlencode(params)
            request = urllib2.Request(self.API_URL, params)
            content = urllib2.urlopen(request, timeout=1).read()
            return json.loads(content)
        except Exception, ex:
            print "调用API接口失败:", str(ex)

if __name__ == "__main__":
    """示例代码入口"""
    SECRET_ID = "your_secret_id" # 产品密钥ID，产品标识
    SECRET_KEY = "your_secret_key" # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "your_business_id" # 业务ID，易盾根据产品业务特点分配
    text_api = TextCheckAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)

    params = {
        "dataId": "ebfcad1c-dba1-490c-b4de-e784c2691768",
        "content": "易盾测试内容！",
        "dataOpType": "1",
        "ip": "123.115.77.137",
        "account": "python@163.com",
        "deviceType": "4",
        "deviceId": "92B1E5AA-4C3D-4565-A8C2-86E297055088",
        "callback": "ebfcad1c-dba1-490c-b4de-e784c2691768",
        "publishTime": str(int(time.time() * 1000))
    }
    ret = text_api.check(params)
    if ret["code"] == 200:
        action = ret["result"]["action"]
        if action == 1:
            print "正常内容，通过"
        elif action == 2:
            print "垃圾内容，删除"
        elif action == 3:
            print "嫌疑内容"
    else:
        print "ERROR: ret.code=%s, ret.msg=%s" % (ret["code"], ret["msg"])
```

```PHP
<?php
/** 产品密钥ID，产品标识 */
define("SECRETID", "your_secret_id");
/** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
define("SECRETKEY", "your_secret_key");
/** 业务ID，易盾根据产品业务特点分配 */
define("BUSINESSID", "your_business_id");
/** 易盾反垃圾云服务文本在线检测接口地址 */
define("API_URL", "https://api.aq.163.com/v2/text/check");
/** api version */
define("VERSION", "v2");
/** API timeout*/
define("API_TIMEOUT", 1);
/** php内部使用的字符串编码 */
define("INTERNAL_STRING_CHARSET", "auto");

/**
 * 计算参数签名
 * $params 请求参数
 * $secretKey secretKey
 */
function gen_signature($secretKey, $params){
    ksort($params);
    $buff="";
    foreach($params as $key=>$value){
        $buff .=$key;
        $buff .=$value;
    }
    $buff .= $secretKey;
    return md5($buff);
}

/**
 * 将输入数据的编码统一转换成utf8
 * @params 输入的参数
 * @inCharset 输入参数对象的编码
 */
function toUtf8($params){
    $utf8s = array();
    foreach ($params as $key => $value) {
      $utf8s[$key] = is_string($value) ? mb_convert_encoding($value, "utf8",INTERNAL_STRING_CHARSET) : $value;
    }
    return $utf8s;
}

/**
 * 反垃圾请求接口简单封装
 * $params 请求参数
 */
function check($params){
    $params["secretId"] = SECRETID;
    $params["businessId"] = BUSINESSID;
    $params["version"] = VERSION;
    $params["timestamp"] = sprintf("%d", round(microtime(true)*1000));// time in milliseconds
    $params["nonce"] = sprintf("%d", rand()); // random int

    $params = toUtf8($params);
    $params["signature"] = gen_signature(SECRETKEY, $params);
    // var_dump($params);

    $options = array(
        'http' => array(
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'timeout' => API_TIMEOUT, // read timeout in seconds
            'content' => http_build_query($params),
        ),
    );
    $context  = stream_context_create($options);
    $result = file_get_contents(API_URL, false, $context);
    return json_decode($result, true);
}

// 简单测试
function main(){
    echo "mb_internal_encoding=".mb_internal_encoding()."\n";
    $params = array(
        "dataId"=>"ebfcad1c-dba1-490c-b4de-e784c2691768",
        "content"=>"易盾测试内容！",
        "dataOpType"=>"1",
        "ip"=>"123.115.77.137",
        "account"=>"php@163.com",
        "deviceType"=>"4",
        "deviceId"=>"92B1E5AA-4C3D-4565-A8C2-86E297055088",
        "callback"=>"ebfcad1c-dba1-490c-b4de-e784c2691768",
        "publishTime"=>round(microtime(true)*1000)
    );

    $ret = check($params);
    var_dump($ret);
    if ($ret["code"] == 200) {
        $action = $ret["result"]["action"];
        if ($action == 1) {// 内容正常，通过
            echo "content is normal\n";
        } else if ($action == 2) {// 垃圾内容，删除
            echo "content is spam\n";
        } else if ($action == 3) {// 嫌疑内容
            echo "content is suspect\n";
        }
    }else{
        // error handler
    }
}

main();
?>


```
```C#
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Com.Netease.Is.Antispam.Demo
{
    class TextCheckApiDemo
    {
        public static void textCheck()
        {
            /** 产品密钥ID，产品标识 */
            String secretId = "your_secret_id";
            /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
            String secretKey = "your_secret_key";
            /** 业务ID，易盾根据产品业务特点分配 */
            String businessId = "your_business_id";
            /** 易盾反垃圾云服务文本在线检测接口地址 */
            String apiUrl = "https://api.aq.163.com/v2/text/check";
            Dictionary<String, String> parameters = new Dictionary<String, String>();

            long curr = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            String time = curr.ToString();

            // 1.设置公共参数
            parameters.Add("secretId", secretId);
            parameters.Add("businessId", businessId);
            parameters.Add("version", "v2");
            parameters.Add("timestamp", time);
            parameters.Add("nonce", new Random().Next().ToString());

            // 2.设置私有参数
            parameters.Add("dataId", "ebfcad1c-dba1-490c-b4de-e784c2691768");
            parameters.Add("content", "易盾测试内容！");
            parameters.Add("dataOpType", "1");
            parameters.Add("ip", "123.115.77.137");
            parameters.Add("account", "csharp@163.com");
            parameters.Add("deviceType", "4");
            parameters.Add("deviceId", "92B1E5AA-4C3D-4565-A8C2-86E297055088");
            parameters.Add("callback", "ebfcad1c-dba1-490c-b4de-e784c2691768");
            parameters.Add("publishTime", time);

            // 3.生成签名信息
            String signature = Utils.genSignature(secretKey, parameters);
            parameters.Add("signature", signature);

            // 4.发送HTTP请求
            HttpClient client = Utils.makeHttpClient();
            String result = Utils.doPost(client, apiUrl, parameters, 1000);
            if(result != null)
            {
                JObject ret = JObject.Parse(result);
                int code = ret.GetValue("code").ToObject<Int32>();
                String msg = ret.GetValue("msg").ToObject<String>();
                if (code == 200)
                {
                    JObject resultObject = (JObject)ret["result"];
                    int action = resultObject["action"].ToObject<Int32>();
                    if (action == 1)
                    {
			            Console.WriteLine("正常内容，通过");
                    }
                    else if (action == 2)
                    {
			            Console.WriteLine("垃圾内容，删除");
                    }
                    else if (action == 3)
                    {
			            Console.WriteLine("嫌疑内容");
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("ERROR: code={0}, msg={1}", code, msg));
                }
            }
            else
            {
                Console.WriteLine("Request failed!");
            }

        }
    }
}
```
```js
var http = null;
var urlutil=require('url');
var querystring = require('querystring');
var crypto = require('crypto');
var md5er = crypto.createHash('md5');//MD5加密工具

//产品密钥ID，产品标识
var secretId="your_secret_id";
// 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
var secretKey="your_secret_key";
// 业务ID，易盾根据产品业务特点分配
var businessId="your_business_id";
// 易盾反垃圾云服务文本在线检测接口地址
var apiurl="https://api.aq.163.com/v2/text/callback/results";
var urlObj=urlutil.parse(apiurl);
var protocol=urlObj.protocol;
var host=urlObj.hostname;
var path=urlObj.path;
var port=urlObj.port;
if(protocol=="https:"){
	http=require('https');
}else{
	console.log("ERROR:portocol parse error, and portocol must be https !");
	return;
}
//产生随机整数--工具方法
var noncer=function(){
	var range=function(start,end){
		var array=[];
		for(var i=start;i<end;++i){
			array.push(i);
		}
		return array;
	};
	var nonce = range(0,6).map(function(x){
		return Math.floor(Math.random()*10);
	}).join('');
	return nonce;
}

//生成签名算法--工具方法
var genSignature=function(secretKey,paramsJson){
	var sorter=function(paramsJson){
		var sortedJson={};
		var sortedKeys=Object.keys(paramsJson).sort();
		for(var i=0;i<sortedKeys.length;i++){
			sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
		}
		return sortedJson;
	}
	var sortedParam=sorter(paramsJson);
	var needSignatureStr="";
	var paramsSortedString=querystring.stringify(sortedParam,'&&',"&&",{
			encodeURIComponent:function(s){
				return s;
			}
		})+secretKey;
	needSignatureStr=paramsSortedString.replace(/&&/g,"");
	md5er.update(needSignatureStr,"UTF-8");
	return md5er.digest('hex');
};
//请求参数
var post_data = {
	// 1.设置公有有参数
	secretId:secretId,
	businessId:businessId,
	version:"v2",
	timestamp:new Date().getTime(),
	nonce:noncer(),
	// 2.设置私有参数
	dataId:"ebfcad1c-dba1-490c-b4de-e784c2691768",
	content:"微xin+8790-",
	dataOpType:"1",
	ip:"123.115.77.137",
	account:"note@163.com",
	deviceType:"4",
	deviceId:"92B1E5AA-4C3D-4565-A8C2-86E297055088",
	callback:"ebfcad1c-dba1-490c-b4de-e784c2691768",
	publishTime:new Date().getTime()
};
var signature=genSignature(secretKey,post_data);
post_data.signature=signature;
var content = querystring.stringify(post_data,null,null,null);
var options = {
    hostname: host,
    port: port,
    path: path,
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Content-Length': Buffer.byteLength(content)
    }
};

var req = http.request(options, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
		var data = JSON.parse(chunk);
		var code=data.code;
		var msg=data.msg;
		if(code==200){
			var result=data.result;
			var action=result.action;
			if(action==1){
				console.log("正常内容，通过")
			}else if(action==2){
				console.log("垃圾内容，删除")
			}else if(action==3){
				console.log("嫌疑内容")
			}
		}else{
			 console.log('ERROR:code=' + code+',msg='+msg);
		}

    });
});
//设置超时
req.setTimeout(1000,function(){
	console.log('request timeout!');
	req.abort();
});
req.on('error', function (e) {
    console.log('request ERROR: ' + e.message);
});
req.write(content);
req.end();
```
### `6.6`响应示例
输出结果：

```json
{
    "code": 200,
    "msg": "ok",
    "result": {
        "action": 1,
        "hitType": 0
    }
}
```

## `7`文本离线结果获取
**********************

### `7.1`接口地址
[https://api.aq.163.com/v2/text/callback/results](https://api.aq.163.com/v2/text/callback/results)
### `7.2`接口描述
该接口用于获取易盾反垃圾云服务离线分析处理结果。通过该接口获取离线处理的数据后，下次调用，不会再次返回之前获取过的数据。接口对请求频率做了限制，请求频率过快服务器会拒绝处理，建议30秒获取一次。

### `7.3`请求参数
该接口参数与请求公共参数一致，详细见 [请求公共参数](#2_1)

### `7.4`响应结果
响应字段如下，响应通用字段已省略，详细见 [响应通用字段](#2_2)：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| result | json数组 | 格式为 json 数组， 数组中每项数据为 json 格式 <br>字段构成如下:<br> callback: 产品调用[文本在线检测](#6)传递的 callback 字段数据。<br> operation :处理结果 0:通过，1:不通过 |

### `7.5`请求示例
```java
/** 产品密钥ID，产品标识 */
String secretId="your_secret_id";
 /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
String secretKey="your_secret_key";
/** 业务ID，易盾根据产品业务特点分配 */
String businessId="your_business_id";
/** 易盾反垃圾云服务文本离线检测结果获取接口地址 */
String apiUrl="https://api.aq.163.com/v2/text/callback/results";
/** 实例化HttpClient，发送http请求使用，可根据需要自行调参 */
HttpClient httpClient = HttpClient4Utils.createHttpClient(100, 20, 10000, 1000, 1000);
Map<String, String> params = new HashMap<String, String>();
// 1.设置公共参数
params.put("secretId", secretId);
params.put("businessId", businessId);
params.put("version", "v2");
params.put("timestamp", String.valueOf(System.currentTimeMillis()));
params.put("nonce", String.valueOf(new Random().nextInt()));

// 2.生成签名信息
String signature = SignatureUtils.genSignature(secretKey, params);
params.put("signature", signature);

// 3.发送HTTP请求，这里使用的是HttpClient工具包，产品可自行选择自己熟悉的工具包发送请求
String response = HttpClient4Utils.sendPost(httpClient, apiUrl, params, Consts.UTF_8);

// 4.解析接口返回值
JsonObject resultObject = new JsonParser().parse(response).getAsJsonObject();
int code = resultObject.get("code").getAsInt();
String msg = resultObject.get("msg").getAsString();
if (code == 200) {
    JsonArray resultArray = resultObject.getAsJsonArray("result");
    for (JsonElement jsonElement : resultArray) {
        JsonObject jObject = jsonElement.getAsJsonObject();
        int operation = jObject.get("operation").getAsInt();
        String callback = jObject.get("callback").getAsString();
        if (operation == 0) {// 内容确认没问题，通过
            System.out.println(String.format("%s，通过", callback));
        } else if (operation == 1) {// 内容非法，不通过，需删除
            System.out.println(String.format("%s，删除", callback));
        }
    }
} else {
    System.out.println(String.format("ERROR: code=%s, msg=%s", code, msg));
}
```
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""易盾文本离线检测结果获取接口python示例代码
接口文档: http://dun.163.com/api.html
python版本：python2.7
运行:
    1. 修改 SECRET_ID,SECRET_KEY,BUSINESS_ID 为对应申请到的值
    2. $ python text_check_callback_demo.py
"""
__author__ = 'yidun-dev'
__date__ = '2016/3/10'
__version__ = '0.1-dev'

import hashlib
import time
import random
import urllib
import urllib2
import json

class TextCheckCallbackAPIDemo(object):
    """文本离线检测获取接口示例代码"""
    API_URL = "https://api.aq.163.com/v2/text/callback/results"
    VERSION = "v2"

    def __init__(self, secret_id, secret_key, business_id):
        """
        Args:
            secret_id (str) 产品密钥ID，产品标识
            secret_key (str) 产品私有密钥，服务端生成签名信息使用
            business_id (str) 业务ID，易盾根据产品业务特点分配
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.business_id = business_id

    def gen_signature(self, params=None):
        """生成签名信息
        Args:
            params (object) 请求参数
        Returns:
            参数签名md5值
        """
        buff = ""
        for k in sorted(params.keys()):
            buff += str(k)+ str(params[k])
        buff += self.secret_key
        return hashlib.md5(buff).hexdigest()

    def check(self):
        """请求易盾接口
        Returns:
            请求结果，json格式
        """
        params = {}
        params["secretId"] = self.secret_id
        params["businessId"] = self.business_id
        params["version"] = self.VERSION
        params["timestamp"] = int(time.time() * 1000)
        params["nonce"] = int(random.random()*100000000)
        params["signature"] = self.gen_signature(params)

        try:
            params = urllib.urlencode(params)
            request = urllib2.Request(self.API_URL, params)
            content = urllib2.urlopen(request, timeout=10).read()
            return json.loads(content)
        except Exception, ex:
            print "调用API接口失败:", str(ex)

if __name__ == "__main__":
    """示例代码入口"""
    SECRET_ID = "your_secret_id" # 产品密钥ID，产品标识
    SECRET_KEY = "your_secret_key" # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "your_business_id" # 业务ID，易盾根据产品业务特点分配
    text_check_callback_api = TextCheckCallbackAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)

    ret = text_check_callback_api.check()

    if ret["code"] == 200:
        for result in ret["result"]:
            print "callback=%s, operation=%s" % (result["callback"], result["operation"])
    else:
        print "ERROR: ret.code=%s, ret.msg=%s" % (ret["code"], ret["msg"])
```

```PHP
<?php
/** 产品密钥ID，产品标识 */
define("SECRETID", "your_secret_id");
/** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
define("SECRETKEY", "your_secret_key");
/** 业务ID，易盾根据产品业务特点分配 */
define("BUSINESSID", "your_business_id");
/** 易盾反垃圾云服务文本离线检测结果获取接口地址 */
define("API_URL", "https://api.aq.163.com/v2/text/callback/results");
/** api version */
define("VERSION", "v2");
/** API timeout*/
define("API_TIMEOUT", 10);
/** php内部使用的字符串编码 */
define("INTERNAL_STRING_CHARSET", "auto");

/**
 * 计算参数签名
 * $params 请求参数
 * $secretKey secretKey
 */
function gen_signature($secretKey, $params){
    ksort($params);
    $buff="";
    foreach($params as $key=>$value){
        $buff .=$key;
        $buff .=$value;
    }
    $buff .= $secretKey;
    return md5($buff);
}

/**
 * 将输入数据的编码统一转换成utf8
 * @params 输入的参数
 * @inCharset 输入参数对象的编码
 */
function toUtf8($params){
    $utf8s = array();
    foreach ($params as $key => $value) {
     $utf8s[$key] = is_string($value) ? mb_convert_encoding($value, "utf8",INTERNAL_STRING_CHARSET) : $value;
   }
   return $utf8s;
}

/**
 * 反垃圾请求接口简单封装
 * $params 请求参数
 */
function check(){
    $params = array();
    $params["secretId"] = SECRETID;
    $params["businessId"] = BUSINESSID;
    $params["version"] = VERSION;
    $params["timestamp"] = sprintf("%d", round(microtime(true)*1000));// time in milliseconds
    $params["nonce"] = sprintf("%d", rand()); // random int

    $params = toUtf8($params);
    $params["signature"] = gen_signature(SECRETKEY, $params);
    // var_dump($params);

    $options = array(
        'http' => array(
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'timeout' => API_TIMEOUT, // read timeout in seconds
            'content' => http_build_query($params),
        ),
    );
    var_dump($params);
    $context  = stream_context_create($options);
    $result = file_get_contents(API_URL, false, $context);
    return json_decode($result, true);
}

// 简单测试
function main(){
    echo "mb_internal_encoding=".mb_internal_encoding()."\n";
    $ret = check();
    var_dump($ret);

    if ($ret["code"] == 200) {
        $result = $ret["result"];
        foreach($result as $index => $value){
            echo "callback".$value["callback"].", operation=".$value["operation"]."\n";
        }
    }else{
        // error handler
    }
}

main();
?>

```
```C#
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Com.Netease.Is.Antispam.Demo
{
    class TextCallbackDemo
    {

        public static void textCallBack()
        {
            /** 产品密钥ID，产品标识 */
            String secretId = "your_secret_id";
            /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
            String secretKey = "your_secret_key";
            /** 业务ID，易盾根据产品业务特点分配 */
            String businessId = "your_business_id";
            /** 易盾反垃圾云服务文本离线检测结果获取接口地址 */
            String apiUrl = "https://api.aq.163.com/v2/text/callback/results";
            Dictionary<String, String> parameters = new Dictionary<String, String>();

            long curr = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            String time = curr.ToString();

            // 1.设置公共参数
            parameters.Add("secretId", secretId);
            parameters.Add("businessId", businessId);
            parameters.Add("version", "v2");
            parameters.Add("timestamp", time);
            parameters.Add("nonce", new Random().Next().ToString());

            // 2.生成签名信息
            String signature = Utils.genSignature(secretKey, parameters);
            parameters.Add("signature", signature);

            // 3.发送HTTP请求
            HttpClient client = Utils.makeHttpClient();
            String result = Utils.doPost(client, apiUrl, parameters, 10000);
            if(result != null)
            {
                JObject ret = JObject.Parse(result);
                int code = ret.GetValue("code").ToObject<Int32>();
                String msg = ret.GetValue("msg").ToObject<String>();
                if (code == 200)
                {
                    JArray array = (JArray)ret.SelectToken("result");
                    foreach (var item in array)
                    {
                        JObject tmp = (JObject)item;
                        int operation = tmp.GetValue("operation").ToObject<Int32>();
                        String callback = tmp.GetValue("callback").ToObject<String>();
                        if (operation == 0)
                        {// 内容确认没问题，通过
                            Console.WriteLine(String.Format("{0},通过", callback));
                        }
                        else if (operation == 1)
                        {// 内容非法，不通过，需删除
                            Console.WriteLine(String.Format("{0},删除", callback));
                        }
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("ERROR: code={0}, msg={1}", code, msg));
                }
            }
            else
            {
                Console.WriteLine("Request failed!");
            }
        }
}
}
```
```js
var http = null;
var urlutil=require('url');
var querystring = require('querystring');
var crypto = require('crypto');
var md5er = crypto.createHash('md5');//MD5加密工具

//产品密钥ID，产品标识
var secretId="your_secret_id";
// 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
var secretKey="your_secret_key";
// 业务ID，易盾根据产品业务特点分配
var businessId="your_business_id";
// 易盾反垃圾云服务文本在线检测接口地址
var apiurl="https://api.aq.163.com/v2/text/callback/results";
var urlObj=urlutil.parse(apiurl);
var protocol=urlObj.protocol;
var host=urlObj.hostname;
var path=urlObj.path;
var port=urlObj.port;
if(protocol=="https:"){
	http=require('https');
}else{
	console.log("ERROR:portocol parse error, and portocol must be https !");
	return;
}

//产生随机整数--工具方法
var noncer=function(){
	var range=function(start,end){
		var array=[];
		for(var i=start;i<end;++i){
			array.push(i);
		}
		return array;
	};
	var nonce = range(0,6).map(function(x){
		return Math.floor(Math.random()*10);
	}).join('');
	return nonce;
}

//生成签名算法--工具方法
var genSignature=function(secretKey,paramsJson){
	var sorter=function(paramsJson){
		var sortedJson={};
		var sortedKeys=Object.keys(paramsJson).sort();
		for(var i=0;i<sortedKeys.length;i++){
			sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
		}
		return sortedJson;
	}
	var sortedParam=sorter(paramsJson);
	var needSignatureStr="";
	var paramsSortedString=querystring.stringify(sortedParam,'&&',"&&",{
			encodeURIComponent:function(s){
				return s;
			}
		})+secretKey;
	needSignatureStr=paramsSortedString.replace(/&&/g,"");
	md5er.update(needSignatureStr,"UTF-8");
	return md5er.digest('hex');
};
//请求参数
var post_data = {
	// 1.设置公有有参数
	secretId:secretId,
	businessId:businessId,
	version:"v2",
	timestamp:new Date().getTime(),
	nonce:noncer()
};
var signature=genSignature(secretKey,post_data);
post_data.signature=signature;
var content = querystring.stringify(post_data,null,null,null);
var options = {
    hostname: host,
    port: port,
    path: path,
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Content-Length': Buffer.byteLength(content)
    }
};

var req = http.request(options, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
        var data = JSON.parse(chunk);
		var code=data.code;
		var msg=data.msg;
		if(code==200){
			var result=data.result;
			if(result.length==0){
				console.log("无数据");
			}else{
				for(var i=0;i<result.length;i++){
					var obj=result[i];
					var callback=obj.callback;
					var operation=obj.operation;
					if(operation==0){// 内容确认没问题，通过
						console.log("正常内容，通过,callback:"+callback)
					}else if(operation==1){// 内容非法，不通过，需删除
						console.log("垃圾内容，删除,callback:"+callback)
					}
				}
			}
		}else{
			 console.log('ERROR:code=' + code+',msg='+msg);
		}
    });
});
//设置超时
req.setTimeout(1000,function(){
	console.log('request timeout!');
	req.abort();
});
req.on('error', function (e) {
    console.log('problem with request: ' + e.message);
});
req.write(content);
req.end();
```

### `7.6`响应示例
输出结果：

```json
{
    "code": 200,
    "msg": "ok",
    "result": [
        {
            "callback": "dataId1234",
            "operation": 0
        },
        {
            "callback": "dataId5678",
            "operation": 1
        }
    ]
}
```

## `8`图片在线检测
*******************

### `8.1`接口地址
[https://api.aq.163.com/v2/image/check](https://api.aq.163.com/v2/image/check)
### `8.2`接口描述
该接口同步返回易盾反垃圾云服务实时反垃圾引擎检测结果，产品根据图片分类结果，做图片初步过滤。由于网络环境及图片本身大小的影响（建议产品对图片进行压缩后，再过反垃圾检测），部分图片可能出现下载超时情况，该部分数据会转到离线检测模块进行机器离线处理，直到得出结果。机器离线检测后，可能会有部分不确定的数据需要人工进一步确认。离线检测结果及人工确认结果需产品自行定期调用[图片离线检测结果获取](#9)获取。

### `8.3`请求参数
公共参数已省略，详细见 [请求公共参数](#2_1)

| 参数名称 | 类型 | 是否必选 | 最大长度 | 描述 |
|----------|------|------|------|------|
| images | String(json数组) | Y | 32张或10MB |images为json数组，支持批量检测|
| account | String | N | 128 |用户唯一标识，如果无需登录则为空 |
| ip | String | N | 32 |用户 IP 地址 |

images参数结构说明

| 字段名称 | 类型 | 是否必选 | 最大长度 | 描述 |
|----------|------|------|------|-----|
| name | String | Y | 1024 |图片名称(或图片标识)， 该字段结构产品可以根据业务情况自行设计，如json结构、或者为图片url均可 |
| type | Number | Y | 4 | 类型，分别为1：图片URL，2:图片BASE64值 |
| data | String | Y | 32张或者10MB | 图片内容，如type=1，则该值为图片URL，如type=2，则该值为图片BASE64值。图片URL检测单次请求最多支持32张，图片BASE64值检测单次请求大小限制为最多10MB |

### `8.4`响应结果
响应字段如下，响应通用字段已省略，详细见 [响应通用字段](#2_2) ：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| result | json | result 为数组，数组里面包括：<br> name：图片名称(或图片标识) <br> labels：分类结果数组，如为空，则表示没有分出类别，如不为空，则表示分类成功，数组字段包括：<br> _label：分类信息，分为100：色情，200：广告，300：暴恐，400：违禁，500：政治敏感<br> level：级别信息，分为1：不确定，2：确定<br> rate：分数_ |

### `8.5`请求示例
```java
/** 产品密钥ID，产品标识 */
String secretId="your_secret_id";
 /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
String secretKey="your_secret_key";
/** 业务ID，易盾根据产品业务特点分配 */
String businessId="your_business_id";
/** 易盾反垃圾云服务图片在线检测接口地址 */
String apiUrl="https://api.aq.163.com/v2/image/check";
/** 实例化HttpClient，发送http请求使用，可根据需要自行调参 */
HttpClient httpClient = HttpClient4Utils.createHttpClient(100, 20, 10000, 1000, 1000);
Map<String, String> params = new HashMap<String, String>();

// 1.设置公共参数
params.put("secretId", secretId);
params.put("businessId", businessId);
params.put("version", "v2");
params.put("timestamp", String.valueOf(System.currentTimeMillis()));
params.put("nonce", String.valueOf(new Random().nextInt()));

// 2.设置私有参数
JsonArray jsonArray = new JsonArray();
// 传图片url进行检测，name结构产品自行设计，用于唯一定位该图片数据
JsonObject image1 = new JsonObject();
image1.addProperty("name", "http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg");
image1.addProperty("type", 1);
image1.addProperty("data", "http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg");
jsonArray.add(image1);

// 传图片base64编码进行检测，name结构产品自行设计，用于唯一定位该图片数据
JsonObject image2 = new JsonObject();
image2.addProperty("name", "{\"imageId\": 33451123, \"contentId\": 78978}");
image2.addProperty("type", 2);
image2.addProperty("data",
                        "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");
jsonArray.add(image2);

params.put("images", jsonArray.toString());
params.put("account", "java@163.com");
params.put("ip", "123.115.77.137");

// 3.生成签名信息
String signature = SignatureUtils.genSignature(secretKey, params);
params.put("signature", signature);

// 4.发送HTTP请求，这里使用的是HttpClient工具包，产品可自行选择自己熟悉的工具包发送请求
String response = HttpClient4Utils.sendPost(httpClient, apiUrl, params, Consts.UTF_8);
System.out.println(response);

// 5.解析接口返回值
JsonObject resultObject = new JsonParser().parse(response).getAsJsonObject();
int code = resultObject.get("code").getAsInt();
String msg = resultObject.get("msg").getAsString();
if (code == 200) {
    JsonArray resultArray = resultObject.getAsJsonArray("result");
    for (JsonElement jsonElement : resultArray) {
        JsonObject jObject = jsonElement.getAsJsonObject();
        String name = jObject.get("name").getAsString();
        System.out.println(name);
        JsonArray labelArray = jObject.get("labels").getAsJsonArray();
        for (JsonElement labelElement : labelArray) {
            JsonObject lObject = labelElement.getAsJsonObject();
            int label = lObject.get("label").getAsInt();
            int level = lObject.get("level").getAsInt();
            double rate = lObject.get("rate").getAsDouble();
            System.out.println(String.format("label:%s, level=%s, rate=%s", label, level, rate));
        }
    }
} else {
    System.out.println(String.format("ERROR: code=%s, msg=%s", code, msg));
}

```

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""易盾图片在线检测接口python示例代码
接口文档: http://dun.163.com/api.html
python版本：python2.7
运行:
    1. 修改 SECRET_ID,SECRET_KEY,BUSINESS_ID 为对应申请到的值
    2. $ python image_check_api_demo.py
"""
__author__ = 'yidun-dev'
__date__ = '2016/3/10'
__version__ = '0.1-dev'

import hashlib
import time
import random
import urllib
import urllib2
import json

class ImageCheckAPIDemo(object):
    """图片在线检测接口示例代码"""
    API_URL = "https://api.aq.163.com/v2/image/check"
    VERSION = "v2"

    def __init__(self, secret_id, secret_key, business_id):
        """
        Args:
            secret_id (str) 产品密钥ID，产品标识
            secret_key (str) 产品私有密钥，服务端生成签名信息使用
            business_id (str) 业务ID，易盾根据产品业务特点分配
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.business_id = business_id

    def gen_signature(self, params=None):
        """生成签名信息
        Args:
            params (object) 请求参数
        Returns:
            参数签名md5值
        """
        buff = ""
        for k in sorted(params.keys()):
            buff += str(k)+ str(params[k])
        buff += self.secret_key
        return hashlib.md5(buff).hexdigest()

    def check(self, params):
        """请求易盾接口
        Args:
            params (object) 请求参数
        Returns:
            请求结果，json格式
        """
        params["secretId"] = self.secret_id
        params["businessId"] = self.business_id
        params["version"] = self.VERSION
        params["timestamp"] = int(time.time() * 1000)
        params["nonce"] = int(random.random()*100000000)
        params["signature"] = self.gen_signature(params)

        # print json.dumps(params)
        try:
            params = urllib.urlencode(params)
            request = urllib2.Request(self.API_URL, params)
            content = urllib2.urlopen(request, timeout=10).read()
            # print content
            return json.loads(content)
        except Exception, ex:
            print "调用API接口失败:", str(ex)

if __name__ == "__main__":
    """示例代码入口"""
    SECRET_ID = "your_secret_id" # 产品密钥ID，产品标识
    SECRET_KEY = "your_secret_key" # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "your_business_id" # 业务ID，易盾根据产品业务特点分配
    image_check_api = ImageCheckAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)

    images = []
    imageurl = {
        "name":"http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg",
        "type":1,
        "data":"http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg"
    }
    imagebase64 = {
        "name":"{\"imageId\": 33451123, \"contentId\": 78978}",
        "type":2,
        "data":"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"
    }
    images.append(imageurl)
    images.append(imagebase64)
    # print json.dumps(images)
    params = {
        "images": json.dumps(images),
        "account": "python@163.com",
        "ip": "123.115.77.137"
    }
    ret = image_check_api.check(params)

    if ret["code"] == 200:
        results = ret["result"]
        for result in results:
            name = result["name"]
            print name
            for label in result["labels"]:
                print "---- label=%s, level=%s, rate=%s" % (label["label"], label["level"], label["rate"])
    else:
        print "ERROR: ret.code=%s, ret.msg=%s" % (ret["code"], ret["msg"])
```
```PHP
<?php
/** 产品密钥ID，产品标识 */
define("SECRETID", "your_secret_id");
/** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
define("SECRETKEY", "your_secret_key");
/** 业务ID，易盾根据产品业务特点分配 */
define("BUSINESSID", "your_business_id");
/** 易盾反垃圾云服务图片在线检测接口地址 */
define("API_URL", "https://api.aq.163.com/v2/image/check");
/** api version */
define("VERSION", "v2");
/** API timeout*/
define("API_TIMEOUT", 10);
/** php内部使用的字符串编码 */
define("INTERNAL_STRING_CHARSET", "auto");

/**
 * 计算参数签名
 * $params 请求参数
 * $secretKey secretKey
 */
function gen_signature($secretKey, $params){
    ksort($params);
    $buff="";
    foreach($params as $key=>$value){
        $buff .=$key;
        $buff .=$value;
    }
    $buff .= $secretKey;
    return md5($buff);
}

/**
 * 将输入数据的编码统一转换成utf8
 * @params 输入的参数
 * @inCharset 输入参数对象的编码
 */
 function toUtf8($params){
     $utf8s = array();
     foreach ($params as $key => $value) {
       $utf8s[$key] = is_string($value) ? mb_convert_encoding($value, "utf8",INTERNAL_STRING_CHARSET) : $value;
     }
     return $utf8s;
 }

/**
 * 反垃圾请求接口简单封装
 * $params 请求参数
 */
function check($params){
    $params["secretId"] = SECRETID;
    $params["businessId"] = BUSINESSID;
    $params["version"] = VERSION;
    $params["timestamp"] = sprintf("%d", round(microtime(true)*1000));// time in milliseconds
    $params["nonce"] = sprintf("%d", rand()); // random int

    $params = toUtf8($params);
    $params["signature"] = gen_signature(SECRETKEY, $params);
    // var_dump($params);

    $options = array(
        "http" => array(
            "header"  => "Content-type: application/x-www-form-urlencoded\r\n",
            "method"  => "POST",
            "timeout" => API_TIMEOUT, // read timeout in seconds
            "content" => http_build_query($params),
        ),
    );
    $context  = stream_context_create($options);
    $result = file_get_contents(API_URL, false, $context);
    // var_dump($result);
    return json_decode($result, true);
}

// 简单测试
function main(){
    echo "mb_internal_encoding=".mb_internal_encoding()."\n";
    $images = array();
    array_push($images, array(// type=1表示传图片url检查
        "name" => "http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg",
        "type" => 1,
        "data" => "http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg",
    ));
    array_push($images, array( // type=2表示传图片base64编码进行检查
        "name" => "{\"imageId\": 33451123, \"contentId\": 78978}",
        "type" => 2,
        "data" => "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"
    ));
    $params = array(
        "images"=>json_encode($images),
        "account"=>"php@163.com",
        "ip"=>"123.115.77.137"
    );
    var_dump($params);

    $ret = check($params);
    var_dump($ret);
    if ($ret["code"] == 200) {
        $result = $ret["result"];
        // var_dump($array);
        foreach($result as $index => $image_ret){
            $name = $image_ret["name"];
            echo "name=".$name."\n";
            foreach($image_ret["labels"] as $index=>$label){
                echo "    label=".$label["label"].", level=".$label["level"].", rate=".$label["rate"]."\n";
            }
        }
    }else{
        // error handler
    }
}
main();
?>

```
```C#
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Com.Netease.Is.Antispam.Demo
{
    class ImageCheckApiDemo
    {
        public static void imageCheck()
        {
            /** 产品密钥ID，产品标识 */
            String secretId = "your_secret_id";
            /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
            String secretKey = "your_secret_key";
            /** 业务ID，易盾根据产品业务特点分配 */
            String businessId = "your_business_id";
            /** 易盾反垃圾云服务图片在线检测接口地址 */
            String apiUrl = "https://api.aq.163.com/v2/image/check";
            Dictionary<String, String> parameters = new Dictionary<String, String>();

            long curr = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            String time = curr.ToString();

            // 1.设置公共参数
            parameters.Add("secretId", secretId);
            parameters.Add("businessId", businessId);
            parameters.Add("version", "v2");
            parameters.Add("timestamp", time);
            parameters.Add("nonce", new Random().Next().ToString());

            // 2.设置私有参数
            JArray jarray = new JArray();
            JObject image1 = new JObject();
            image1.Add("name", "http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg");
            image1.Add("type", 1);
            image1.Add("data", "http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg");
            jarray.Add(image1);

            JObject image2 = new JObject();
            image2.Add("name", "{\"imageId\": 33451123, \"contentId\": 78978}");
            image2.Add("type", 2);
            image2.Add("data", "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");
            jarray.Add(image2);

            parameters.Add("images", jarray.ToString());
            parameters.Add("account", "charp@163.com");
            parameters.Add("ip", "123.115.77.137");

            // 3.生成签名信息
            String signature = Utils.genSignature(secretKey, parameters);
            parameters.Add("signature", signature);

            // 4.发送HTTP请求
            HttpClient client = Utils.makeHttpClient();
            String result = Utils.doPost(client, apiUrl, parameters, 1000);
            if(result != null)
            {
                JObject ret = JObject.Parse(result);
                int code = ret.GetValue("code").ToObject<Int32>();
                String msg = ret.GetValue("msg").ToObject<String>();
                if (code == 200)
                {
                    JArray array = (JArray)ret.SelectToken("result");
                    foreach (var item in array)
                    {
                        JObject tmp = (JObject)item;
                        String name = tmp.GetValue("name").ToObject<String>();
                        JArray labels = (JArray)tmp.SelectToken("labels");
                        foreach (var lable in labels)
                        {
                            JObject lableData = (JObject)lable;
                            int label = lableData.GetValue("label").ToObject<Int32>();
                            int level = lableData.GetValue("level").ToObject<Int32>();
                            double rate = lableData.GetValue("rate").ToObject<Double>();
                            Console.WriteLine(String.Format("label:{0}, level={1}, rate={2}", label, level, rate));
                        }
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("ERROR: code={0}, msg={1}", code, msg));
                }
            }
            else
            {
                Console.WriteLine("Request failed!");
            }
        }
    }
}
```
```js
var http = null;
var urlutil=require('url');
var querystring = require('querystring');
var crypto = require('crypto');
var md5er = crypto.createHash('md5');//MD5加密工具

//产品密钥ID，产品标识
var secretId="your_secret_id";
// 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
var secretKey="your_secret_key";
// 业务ID，易盾根据产品业务特点分配
var businessId="your_business_id";
// 易盾反垃圾云服务文本在线检测接口地址
var apiurl="https://api.aq.163.com/v2/image/check";
var urlObj=urlutil.parse(apiurl);
var protocol=urlObj.protocol;
var host=urlObj.hostname;
var path=urlObj.path;
var port=urlObj.port;
if(protocol=="https:"){
	http=require('https');
}else{
	console.log("ERROR:portocol parse error, and portocol must be https !");
	return;
}

//产生随机整数--工具方法
var noncer=function(){
	var range=function(start,end){
		var array=[];
		for(var i=start;i<end;++i){
			array.push(i);
		}
		return array;
	};
	var nonce = range(0,6).map(function(x){
		return Math.floor(Math.random()*10);
	}).join('');
	return nonce;
}

//生成签名算法--工具方法
var genSignature=function(secretKey,paramsJson){
	var sorter=function(paramsJson){
		var sortedJson={};
		var sortedKeys=Object.keys(paramsJson).sort();
		for(var i=0;i<sortedKeys.length;i++){
			sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
		}
		return sortedJson;
	}
	var sortedParam=sorter(paramsJson);
	var needSignatureStr="";
	var paramsSortedString=querystring.stringify(sortedParam,'&&',"&&",{
			encodeURIComponent:function(s){
				return s;
			}
		})+secretKey;
	needSignatureStr=paramsSortedString.replace(/&&/g,"");
	md5er.update(needSignatureStr,"UTF-8");
	return md5er.digest('hex');
};

//请求参数
var post_data = {
	// 1.设置公有有参数
	secretId:secretId,
	businessId:businessId,
	version:"v2",
	timestamp:new Date().getTime(),
	nonce:noncer(),
	// 2.1设置私有参数
	account:"nodejs@163.com",
	ip:"123.115.77.137"
};
// 2.2请求图片参数
var images=[{
		name:"http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg",
		type:1,
		data:"http://p1.music.126.net/lEQvXzoC17AFKa6yrf-ldA==/1412872446212751.jpg"
	},{
		name:"{\"imageId\": 33451123, \"contentId\": 78978}",
		type:2,
		data:"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"
	}];
post_data.images=JSON.stringify(images);
var signature=genSignature(secretKey,post_data);
post_data.signature=signature;
var content = querystring.stringify(post_data,null,null,null);
var options = {
    hostname: host,
    port: port,
    path: path,
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Content-Length': Buffer.byteLength(content)
    }
};

var req = http.request(options, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
        var data = JSON.parse(chunk);
		var code=data.code;
		var msg=data.msg;
		if(code==200){
			var result=data.result;
			if(result.length==0){
				console.log("无数据");
			}else{
				for(var i=0;i<result.length;i++){
					var obj=result[i];
					var name=obj.name;
					console.log("name="+name);
					var labelsArray=obj.labels;
					for(var k=0;k<labelsArray.length;k++){
						var labelObj=labelsArray[k];
						var label=labelObj.label;
						var level=labelObj.level;
						var rate=labelObj.rate;
						console.log("lable:"+label+",level:"+level+",rate:"+rate);
					}

				}
			}
		}else{
			 console.log('ERROR:code=' + code+',msg='+msg);
		}
    });
});
//设置超时
req.setTimeout(1000,function(){
	console.log('request timeout!');
	req.abort();
});
req.on('error', function (e) {
    console.log('problem with request: ' + e.message);
});
req.write(content);
req.end();
```
### `8.6`响应示例
输出结果：

```json
{
    "code": 200,
    "msg": "ok",
    "result": [
        {
            "name": "http://img1.cache.netease.com/xxx1.jpg",
            "labels": [ ]
        },
        {
            "name": "http://img1.cache.netease.com/xxx2.jpg",
            "labels": [
                {
                    "label": 100,
                    "level": 2,
                    "rate": 0.99
                },
                {
                    "label": 200,
                    "level": 1,
                    "rate": 0.5
                }
            ]
        },
        {
            "name": "http://img1.cache.netease.com/xxx3.jpg",
            "labels": [
                {
                    "label": 200,
                    "level": 1,
                    "rate": 0.5
                }
            ]
        }
    ]
}
```

## `9`图片离线结果获取
*********************

### `9.1`接口地址
[https://api.aq.163.com/v2/image/callback/results](https://api.aq.163.com/v2/image/callback/results)

### `9.2`接口描述
该接口用于获取易盾反垃圾云服务离线分析处理结果。通过该接口获取离线处理的数据后，下次调用，不会再次返回之前获取过的数据。接口对请求频率做了限制，请求频率过快服务器会拒绝处理，建议30秒获取一次。

### `9.3`请求参数
该接口参数与请求公共参数一致，详细见 [请求公共参数](#2_1)

### `9.4`响应结果
响应字段如下，响应通用字段已省略，详细见 [响应通用字段](#2_2)：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| result | json数组 | result 为数组，数组里面包括：<br> name：图片名称(或图片标识) <br> labels：分类结果数组，如为空，则表示没有分出类别，如不为空，则表示分类成功，数组字段包括：<br> _label：分类信息，分为100：色情，200：广告，300：暴恐，400：违禁，500：政治敏感，0：无分类<br> level：级别信息，分为1：不确定，2：确定<br> rate：分数_ |

### `9.5`请求示例
```java
/** 产品密钥ID，产品标识 */
String secretId="your_secret_id";
 /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
String secretKey="your_secret_key";
/** 业务ID，易盾根据产品业务特点分配 */
String businessId="your_business_id";
/** 易盾反垃圾云服务图片离线检测结果获取接口地址 */
String apiUrl="https://api.aq.163.com/v2/image/callback/results";
/** 实例化HttpClient，发送http请求使用，可根据需要自行调参 */
HttpClient httpClient = HttpClient4Utils.createHttpClient(100, 20, 10000, 1000, 1000);
Map<String, String> params = new HashMap<String, String>();

// 1.设置公共参数
params.put("secretId", secretId);
params.put("businessId", businessId);
params.put("version", "v2");
params.put("timestamp", String.valueOf(System.currentTimeMillis()));
params.put("nonce", String.valueOf(new Random().nextInt()));

// 2.生成签名信息
String signature = SignatureUtils.genSignature(secretKey, params);
params.put("signature", signature);

// 3.发送HTTP请求，这里使用的是HttpClient工具包，产品可自行选择自己熟悉的工具包发送请求
String response = HttpClient4Utils.sendPost(httpClient, apiUrl, params, Consts.UTF_8);

// 4.解析接口返回值
JsonObject resultObject = new JsonParser().parse(response).getAsJsonObject();
int code = resultObject.get("code").getAsInt();
String msg = resultObject.get("msg").getAsString();
if (code == 200) {
    JsonArray resultArray = resultObject.getAsJsonArray("result");
    for (JsonElement jsonElement : resultArray) {
        JsonObject jObject = jsonElement.getAsJsonObject();
        String name = jObject.get("name").getAsString();
        System.out.println(name);
        JsonArray labelArray = jObject.get("labels").getAsJsonArray();
        for (JsonElement labelElement : labelArray) {
            JsonObject lObject = labelElement.getAsJsonObject();
            int label = lObject.get("label").getAsInt();
            int level = lObject.get("level").getAsInt();
            double rate = lObject.get("rate").getAsDouble();
            System.out.println(String.format("label:%s, level=%s, rate=%s", label, level, rate));
        }
    }
} else {
    System.out.println(String.format("ERROR: code=%s, msg=%s", code, msg));
}

```

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""易盾图片离线检测结果获取接口python示例代码
接口文档: http://dun.163.com/api.html
python版本：python2.7
运行:
    1. 修改 SECRET_ID,SECRET_KEY,BUSINESS_ID 为对应申请到的值
    2. $ python image_check_callback_demo.py
"""
__author__ = 'yidun-dev'
__date__ = '2016/3/10'
__version__ = '0.1-dev'

import hashlib
import time
import random
import urllib
import urllib2
import json

class ImageCheckCallbackAPIDemo(object):
    """易盾图片离线检测结果获取接口示例代码"""
    API_URL = "https://api.aq.163.com/v2/image/callback/results"
    VERSION = "v2"

    def __init__(self, secret_id, secret_key, business_id):
        """
        Args:
            secret_id (str) 产品密钥ID，产品标识
            secret_key (str) 产品私有密钥，服务端生成签名信息使用
            business_id (str) 业务ID，易盾根据产品业务特点分配
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.business_id = business_id

    def gen_signature(self, params=None):
        """生成签名信息
        Args:
            params (object) 请求参数
        Returns:
            参数签名md5值
        """
        buff = ""
        for k in sorted(params.keys()):
            buff += str(k)+ str(params[k])
        buff += self.secret_key
        return hashlib.md5(buff).hexdigest()

    def check(self):
        """请求易盾接口
        Returns:
            请求结果，json格式
        """
        params = {}
        params["secretId"] = self.secret_id
        params["businessId"] = self.business_id
        params["version"] = self.VERSION
        params["timestamp"] = int(time.time() * 1000)
        params["nonce"] = int(random.random()*100000000)
        params["signature"] = self.gen_signature(params)

        try:
            params = urllib.urlencode(params)
            request = urllib2.Request(self.API_URL, params)
            content = urllib2.urlopen(request, timeout=10).read()
            # print content
            return json.loads(content)
        except Exception, ex:
            print "调用API接口失败:", str(ex)

if __name__ == "__main__":
    """示例代码入口"""
    SECRET_ID = "your_secret_id" # 产品密钥ID，产品标识
    SECRET_KEY = "your_secret_key" # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "your_business_id" # 业务ID，易盾根据产品业务特点分配
    image_check_callback_api = ImageCheckCallbackAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)

    ret = image_check_callback_api.check()

    if ret["code"] == 200:
        results = ret["result"]
        for result in results:
            name = result["name"]
            print name
            for label in result["labels"]:
                print "---- label=%s, level=%s, rate=%s" % (label["label"], label["level"], label["rate"])
    else:
        print "ERROR: ret.code=%s, ret.msg=%s" % (ret["code"], ret["msg"])
```

```PHP
<?php
/** 产品密钥ID，产品标识 */
define("SECRETID", "your_secret_id");
/** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
define("SECRETKEY", "your_secret_key");
/** 业务ID，易盾根据产品业务特点分配 */
define("BUSINESSID", "your_business_id");
/** 易盾反垃圾云服务图片离线检测结果获取接口地址 */
define("API_URL", "https://api.aq.163.com/v2/image/callback/results");
/** api version */
define("VERSION", "v2");
/** API timeout*/
define("API_TIMEOUT", 10);
/** php内部使用的字符串编码 */
define("INTERNAL_STRING_CHARSET", "auto");

/**
 * 计算参数签名
 * $params 请求参数
 * $secretKey secretKey
 */
function gen_signature($secretKey, $params){
    ksort($params);
    $buff="";
    foreach($params as $key=>$value){
        $buff .=$key;
        $buff .=$value;
    }
    $buff .= $secretKey;
    return md5($buff);
}

/**
 * 将输入数据的编码统一转换成utf8
 * @params 输入的参数
 * @inCharset 输入参数对象的编码
 */
function toUtf8($params){
    $utf8s = array();
    foreach ($params as $key => $value) {
      $utf8s[$key] = is_string($value) ? mb_convert_encoding($value, "utf8",INTERNAL_STRING_CHARSET) : $value;
    }
    return $utf8s;
}

/**
 * 反垃圾请求接口简单封装
 * $params 请求参数
 */
function check(){
    $params = array();
    $params["secretId"] = SECRETID;
    $params["businessId"] = BUSINESSID;
    $params["version"] = VERSION;
    $params["timestamp"] = sprintf("%d", round(microtime(true)*1000));// time in milliseconds
    $params["nonce"] = sprintf("%d", rand()); // random int

    $params = toUtf8($params);
    $params["signature"] = gen_signature(SECRETKEY, $params);
    // var_dump($params);

    $options = array(
        'http' => array(
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'timeout' => API_TIMEOUT, // read timeout in seconds
            'content' => http_build_query($params),
        ),
    );
    $context  = stream_context_create($options);
    $result = file_get_contents(API_URL, false, $context);
    return json_decode($result, true);
}

// 简单测试
function main(){
    echo "mb_internal_encoding=".mb_internal_encoding()."\n";
    $ret = check();
    var_dump($ret);

    if ($ret["code"] == 200) {
        $result = $ret["result"];
        // var_dump($array);
        foreach($result as $index => $image_ret){
            $name = $image_ret["name"];
            echo "name=".$name."\n";
            foreach($image_ret["labels"] as $index=>$label){
                echo "    label=".$label["label"].", level=".$label["level"].", rate=".$label["rate"]."\n";
            }
        }
    }else{
        // error handler
    }
}

main();
?>

```

```C#
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Com.Netease.Is.Antispam.Demo
{
    class ImageCallbackDemo
    {
        public static void imageCallBack()
        {
            /** 产品密钥ID，产品标识 */
            String secretId = "your_secret_id";
            /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
            String secretKey = "your_secret_key";
            /** 业务ID，易盾根据产品业务特点分配 */
            String businessId = "your_business_id";
            /** 易盾反垃圾云服务图片离线检测结果获取接口地址 */
            String apiUrl = "https://api.aq.163.com/v2/image/callback/results";
            Dictionary<String, String> parameters = new Dictionary<String, String>();

            long curr = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            String time = curr.ToString();

            // 1.设置公共参数
            parameters.Add("secretId", secretId);
            parameters.Add("businessId", businessId);
            parameters.Add("version", "v2");
            parameters.Add("timestamp", time);
            parameters.Add("nonce", new Random().Next().ToString());

            // 2.生成签名信息
            String signature = Utils.genSignature(secretKey, parameters);
            parameters.Add("signature", signature);

            // 3.发送HTTP请求
            HttpClient client = Utils.makeHttpClient();
            String result = Utils.doPost(client, apiUrl, parameters, 10000);
            if(result != null)
            {
                JObject ret = JObject.Parse(result);
                int code = ret.GetValue("code").ToObject<Int32>();
                String msg = ret.GetValue("msg").ToObject<String>();
                if (code == 200)
                {
                    JArray array = (JArray)ret.SelectToken("result");
                    foreach (var item in array)
                    {
                        JObject tmp = (JObject)item;
                        String name = tmp.GetValue("name").ToObject<String>();
                        JArray labels = (JArray)tmp.SelectToken("labels");
                        foreach (var lable in labels)
                        {
                            JObject lableData = (JObject)lable;
                            int label = lableData.GetValue("label").ToObject<Int32>();
                            int level = lableData.GetValue("level").ToObject<Int32>();
                            double rate = lableData.GetValue("rate").ToObject<Double>();
                            Console.WriteLine(String.Format("label:{0}, level={1}, rate={2}", label, level, rate));
                        }
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("ERROR: code={0}, msg={1}", code, msg));
                }
            }
            else
            {
                Console.WriteLine("Request failed!");
            }

        }
    }
}
```
```js
var http = null;
var urlutil=require('url');
var querystring = require('querystring');
var crypto = require('crypto');
var md5er = crypto.createHash('md5');//MD5加密工具

//产品密钥ID，产品标识
var secretId="your_secret_id";
// 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
var secretKey="your_secret_key";
// 业务ID，易盾根据产品业务特点分配
var businessId="your_business_id";
// 易盾反垃圾云服务文本在线检测接口地址
var apiurl="https://api.aq.163.com/v2/image/callback/results";
var urlObj=urlutil.parse(apiurl);
var protocol=urlObj.protocol;
var host=urlObj.hostname;
var path=urlObj.path;
var port=urlObj.port;
if(protocol=="https:"){
	http=require('https');
}else{
	console.log("ERROR:portocol parse error, and portocol must be https !");
	return;
}
//产生随机整数--工具方法
var noncer=function(){
	var range=function(start,end){
		var array=[];
		for(var i=start;i<end;++i){
			array.push(i);
		}
		return array;
	};
	var nonce = range(0,6).map(function(x){
		return Math.floor(Math.random()*10);
	}).join('');
	return nonce;
}

//生成签名算法--工具方法
var genSignature=function(secretKey,paramsJson){
	var sorter=function(paramsJson){
		var sortedJson={};
		var sortedKeys=Object.keys(paramsJson).sort();
		for(var i=0;i<sortedKeys.length;i++){
			sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
		}
		return sortedJson;
	}
	var sortedParam=sorter(paramsJson);
	var needSignatureStr="";
	var paramsSortedString=querystring.stringify(sortedParam,'&&',"&&",{
			encodeURIComponent:function(s){
				return s;
			}
		})+secretKey;
	needSignatureStr=paramsSortedString.replace(/&&/g,"");
	md5er.update(needSignatureStr,"UTF-8");
	return md5er.digest('hex');
};

//请求参数
var post_data = {
	// 1.设置公有有参数
	secretId:secretId,
	businessId:businessId,
	version:"v2",
	timestamp:new Date().getTime(),
	nonce:noncer()
}
var signature=genSignature(secretKey,post_data);
post_data.signature=signature;
var content = querystring.stringify(post_data,null,null,null);
var options = {
    hostname: host,
    port: port,
    path: path,
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Content-Length': Buffer.byteLength(content)
    }
};

var req = http.request(options, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
       var data = JSON.parse(chunk);
		var code=data.code;
		var msg=data.msg;
		if(code==200){
			var result=data.result;
			if(result.length==0){
				console.log("无数据");
			}else{
				for(var i=0;i<result.length;i++){
					var obj=result[i];
					var name=obj.name;
					console.log("name="+name);
					var labelsArray=obj.labels;
					for(var k=0;k<labelsArray.length;k++){
						var labelObj=labelsArray[k];
						var label=labelObj.label;
						var level=labelObj.level;
						var rate=labelObj.rate;
						console.log("lable:"+label+",level:"+level+",rate:"+rate);
					}

				}
			}
		}else{
			 console.log('ERROR:code=' + code+',msg='+msg);
		}
    });
});
//设置超时
req.setTimeout(1000,function(){
	console.log('request timeout!');
	req.abort();
});
req.on('error', function (e) {
    console.log('problem with request: ' + e.message);
});
req.write(content);
req.end();
```

### `9.6`响应示例
输出结果：

```json
{
    "code": 200,
    "msg": "ok",
    "result": [
        {
            "name": "http://img1.cache.netease.com/xxx1.jpg",
            "labels": [ ]
        },
        {
            "name": "http://img1.cache.netease.com/xxx2.jpg",
            "labels": [
                {
                    "label": 100,
                    "level": 2,
                    "rate": 0.99
                },
                {
                    "label": 200,
                    "level": 1,
                    "rate": 0.5
                }
            ]
        },
        {
            "name": "http://img1.cache.netease.com/xxx3.jpg",
            "labels": [
                {
                    "label": 200,
                    "level": 1,
                    "rate": 0.5
                }
            ]
        },
        {
            "name": "http://img1.cache.netease.com/xxx4.jpg",
            "labels": [
                {
                    "label": 300,
                    "level": 1,
                    "rate": 0.5
                }
            ]
        }
    ]
}
```

## `10`直播流信息提交
*******************

### `10.1`接口地址
[https://api.aq.163.com/v2/livevideo/submit](https://api.aq.163.com/v2/livevideo/submit)
### `10.2`接口描述
提交直播流相关信息接口，信息提交后，易盾会异步检测直播是否违规，检测结果需产品自行定期调用[直播流结果获取](#11)接口获取。

### `10.3`请求参数
公共参数已省略，详细见 [请求公共参数](#2_1)

| 参数名称 | 类型 | 是否必选 | 最大长度 | 描述 |
|----------|------|------|------|------|
| url | String | Y | 512 | 直播流地址 |
| dataId | String | Y | 128 | 直播流唯一标识 |
| callback | String | Y | 512 | 数据回调参数，产品根据业务情况自行设计，当获取离线检测结果时，易盾反垃圾云服务会返回该字段 |

### `10.4`响应结果
响应字段如下，响应通用字段已省略，详细见 [响应通用字段](#2_2) ：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| result | Boolean | true表示提交成功，false表示提交失败 |

### `10.5`请求示例
```java
/*
 * @(#) LiveVideoCheckAPIDemo.java 2016年8月1日
 *
 * Copyright 2010 NetEase.com, Inc. All rights reserved.
 */
package com.netease.is.antispam.demo.v2;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.http.Consts;
import org.apache.http.client.HttpClient;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.netease.is.antispam.demo.utils.HttpClient4Utils;
import com.netease.is.antispam.demo.utils.SignatureUtils;

/**
 * 调用易盾反垃圾云服务直播流信息提交接口API示例，该示例依赖以下jar包：
 * 1. httpclient，用于发送http请求
 * 2. commons-codec，使用md5算法生成签名信息，详细见SignatureUtils.java
 * 3. gson，用于做json解析
 *
 * @author mg
 * @version 2016年8月1日
 */
public class LiveVideoSubmitAPIDemo {
    /** 产品密钥ID，产品标识 */
    private final static String SECRETID = "your_secret_id";
    /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
    private final static String SECRETKEY = "your_secret_key";
    /** 业务ID，易盾根据产品业务特点分配 */
    private final static String BUSINESSID = "your_business_id";
    /** 易盾反垃圾云服务直播流信息提交接口地址 */
    private final static String API_URL = "https://api.aq.163.com/v2/livevideo/submit";
    /** 实例化HttpClient，发送http请求使用，可根据需要自行调参 */
    private static HttpClient httpClient = HttpClient4Utils.createHttpClient(100, 20, 1000, 1000, 1000);

    public static void main(String[] args) throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        // 1.设置公共参数
        params.put("secretId", SECRETID);
        params.put("businessId", BUSINESSID);
        params.put("version", "v2");
        params.put("timestamp", String.valueOf(System.currentTimeMillis()));
        params.put("nonce", String.valueOf(new Random().nextInt()));

        // 2.设置私有参数
        params.put("url", "http://xxx.xxx.com/xxxx");
        params.put("dataId", "fbfcad1c-dba1-490c-b4de-e784c2691765");
        params.put("callback", "{\"p\":\"xx\"}");

        // 3.生成签名信息
        String signature = SignatureUtils.genSignature(SECRETKEY, params);
        params.put("signature", signature);

        // 4.发送HTTP请求，这里使用的是HttpClient工具包，产品可自行选择自己熟悉的工具包发送请求
        String response = HttpClient4Utils.sendPost(httpClient, API_URL, params, Consts.UTF_8);

        // 5.解析接口返回值
        JsonObject jObject = new JsonParser().parse(response).getAsJsonObject();
        int code = jObject.get("code").getAsInt();
        String msg = jObject.get("msg").getAsString();
        if (code == 200) {
            boolean result = jObject.get("result").getAsBoolean();
            if (result) {
                System.out.println("推送成功!");
            } else {
                System.out.println("推送失败!");
            }
        } else {
            System.out.println(String.format("ERROR: code=%s, msg=%s", code, msg));
        }
    }
}

```
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""易盾视频直播流信息提交接口python示例代码
接口文档: http://dun.163.com/api.html
python版本：python2.7
运行:
    1. 修改 SECRET_ID,SECRET_KEY,BUSINESS_ID 为对应申请到的值
    2. $ python check.py
"""
__author__ = 'yidun-dev'
__date__ = '2016/3/10'
__version__ = '0.1-dev'

import hashlib
import time
import random
import urllib
import urllib2
import json

class LiveVideoAPIDemo(object):
    """视频直播流信息提交接口示例代码"""
    API_URL = "https://api.aq.163.com/v2/livevideo/submit"
    VERSION = "v2"

    def __init__(self, secret_id, secret_key, business_id):
        """
        Args:
            secret_id (str) 产品密钥ID，产品标识
            secret_key (str) 产品私有密钥，服务端生成签名信息使用
            business_id (str) 业务ID，易盾根据产品业务特点分配
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.business_id = business_id

    def gen_signature(self, params=None):
        """生成签名信息
        Args:
            params (object) 请求参数
        Returns:
            参数签名md5值
        """
        buff = ""
        for k in sorted(params.keys()):
            buff += str(k)+ str(params[k])
        buff += self.secret_key
        return hashlib.md5(buff).hexdigest()

    def check(self, params):
        """请求易盾接口
        Args:
            params (object) 请求参数
        Returns:
            请求结果，json格式
        """
        params["secretId"] = self.secret_id
        params["businessId"] = self.business_id
        params["version"] = self.VERSION
        params["timestamp"] = int(time.time() * 1000)
        params["nonce"] = int(random.random()*100000000)
        params["signature"] = self.gen_signature(params)

        try:
            params = urllib.urlencode(params)
            request = urllib2.Request(self.API_URL, params)
            content = urllib2.urlopen(request, timeout=1).read()
            return json.loads(content)
        except Exception, ex:
            print "调用API接口失败:", str(ex)

if __name__ == "__main__":
    """示例代码入口"""
    SECRET_ID = "your_secret_id" # 产品密钥ID，产品标识
    SECRET_KEY = "your_secret_key" # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "your_business_id" # 业务ID，易盾根据产品业务特点分配
    api = LiveVideoAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)

    params = {
        "dataId": "fbfcad1c-dba1-490c-b4de-e784c2691765",
        "url": "http://xxx.xxx.com/xxxx",
        "callback": "{\"p\":\"xx\"}"
    }

    ret = api.check(params)
    if ret["code"] == 200:
        print "提交视频直播流结果: %s" % ret["result"]
    else:
        print "ERROR: ret.code=%s, ret.msg=%s" % (ret["code"], ret["msg"])
```
```PHP
<?php
/** 产品密钥ID，产品标识 */
define("SECRETID", "your_secret_id");
/** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
define("SECRETKEY", "your_secret_key");
/** 业务ID，易盾根据产品业务特点分配 */
define("BUSINESSID", "your_business_id");
/** 易盾反垃圾云服务直播视频检测接口地址 */
define("API_URL", "https://api.aq.163.com/v2/livevideo/submit");
/** api version */
define("VERSION", "v2");
/** API timeout*/
define("API_TIMEOUT", 1);
/** php内部使用的字符串编码 */
define("INTERNAL_STRING_CHARSET", "auto");
/**
 * 计算参数签名
 * $params 请求参数
 * $secretKey secretKey
 */
function gen_signature($secretKey, $params){
	ksort($params);
	$buff="";
	foreach($params as $key=>$value){
		$buff .=$key;
		$buff .=$value;
	}
	$buff .= $secretKey;
	return md5($buff);
}
/**
 * 将输入数据的编码统一转换成utf8
 * @params 输入的参数
 */
function toUtf8($params){
	$utf8s = array();
    foreach ($params as $key => $value) {
    	$utf8s[$key] = is_string($value) ? mb_convert_encoding($value, "utf8", INTERNAL_STRING_CHARSET) : $value;
    }
    return $utf8s;
}
/**
 * 反垃圾请求接口简单封装
 * $params 请求参数
 */
function submit($params){
	$params["secretId"] = SECRETID;
	$params["businessId"] = BUSINESSID;
	$params["version"] = VERSION;
	$params["timestamp"] = sprintf("%d", round(microtime(true)*1000));// time in milliseconds
	$params["nonce"] = sprintf("%d", rand()); // random int
	$params = toUtf8($params);
	$params["signature"] = gen_signature(SECRETKEY, $params);
	// var_dump($params);
	$options = array(
	    'http' => array(
	        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
	        'method'  => 'POST',
	        'timeout' => API_TIMEOUT, // read timeout in seconds
	        'content' => http_build_query($params),
	    ),
	);
	$context  = stream_context_create($options);
	$result = file_get_contents(API_URL, false, $context);
	return json_decode($result, true);
}
// 简单测试
function main(){
    echo "mb_internal_encoding=".mb_internal_encoding()."\n";
	$params = array(
		"dataId"=>"fbfcad1c-dba1-490c-b4de-e784c2691765",
		"url"=>"http://xxx.xxx.com/xxxx",
		"callback"=>"{\"p\":\"xx\"}",
	);
	$ret = submit($params);
	var_dump($ret);
	if ($ret["code"] == 200) {
		$result = $ret["result"];
		echo "result = $result";
    }else{
    	// error handler
    }
}
main();
?>
```
```c#
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Com.Netease.Is.Antispam.Demo
{
    class LiveVideoSubmitApiDemo
    {

        public static void liveVideoSubmit()
        {
            /** 产品密钥ID，产品标识 */
            String secretId = "your_secret_id";
            /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
            String secretKey = "your_secret_key";
            /** 业务ID，易盾根据产品业务特点分配 */
            String businessId = "your_business_id";
            /** 易盾反垃圾云服务直播流信息提交接口地址  */
            String apiUrl = "https://api.aq.163.com/v2/livevideo/submit";
            Dictionary<String, String> parameters = new Dictionary<String, String>();

            long curr = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            String time = curr.ToString();

            // 1.设置公共参数
            parameters.Add("secretId", secretId);
            parameters.Add("businessId", businessId);
            parameters.Add("version", "v2");
            parameters.Add("timestamp", time);
            parameters.Add("nonce", new Random().Next().ToString());

            // 2.设置私有参数
            parameters.Add("url", "http://xxx.xxx.com/xxxx");
            parameters.Add("dataId", "fbfcad1c-dba1-490c-b4de-e784c2691765");
            parameters.Add("callback", "{\"p\":\"xx\"}");

            // 3.生成签名信息
            String signature = Utils.genSignature(secretKey, parameters);
            parameters.Add("signature", signature);

            // 4.发送HTTP请求
            HttpClient client = Utils.makeHttpClient();
            String result = Utils.doPost(client, apiUrl, parameters, 1000);
            if(result != null)
            {
                JObject ret = JObject.Parse(result);
                int code = ret.GetValue("code").ToObject<Int32>();
                String msg = ret.GetValue("msg").ToObject<String>();
                if (code == 200)
                {
                    Boolean re = ret.GetValue("result").ToObject<Boolean>();
                    if(re == true)
                    {
                        Console.WriteLine("推送成功!");
                    }
                    else
                    {
                        Console.WriteLine("推送失败!");
                    }

                }
                else
                {
                    Console.WriteLine(String.Format("ERROR: code={0}, msg={1}", code, msg));
                }
            }
            else
            {
                Console.WriteLine("Request failed!");
            }

        }
    }
}
```
```js
var http = null;
var urlutil=require('url');
var querystring = require('querystring');
var crypto = require('crypto');
var md5er = crypto.createHash('md5');//MD5加密工具

//产品密钥ID，产品标识
var secretId="your_secret_id";
// 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
var secretKey="your_secret_key";
// 业务ID，易盾根据产品业务特点分配
var businessId="your_business_id";
// 易盾反垃圾云服务直播流信息提交接口地址
var apiurl="https://api.aq.163.com/v2/livevideo/submit";
var urlObj=urlutil.parse(apiurl);
var protocol=urlObj.protocol;
var host=urlObj.hostname;
var path=urlObj.path;
var port=urlObj.port;
if(protocol=="https:"){
	http=require('https');
}else{
	console.log("ERROR:portocol parse error, and portocol must be https !");
	return;
}
//产生随机整数--工具方法
var noncer=function(){
	var range=function(start,end){
		var array=[];
		for(var i=start;i<end;++i){
			array.push(i);
		}
		return array;
	};
	var nonce = range(0,6).map(function(x){
		return Math.floor(Math.random()*10);
	}).join('');
	return nonce;
}

//生成签名算法--工具方法
var genSignature=function(secretKey,paramsJson){
	var sorter=function(paramsJson){
		var sortedJson={};
		var sortedKeys=Object.keys(paramsJson).sort();
		for(var i=0;i<sortedKeys.length;i++){
			sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
		}
		return sortedJson;
	}
	var sortedParam=sorter(paramsJson);
	var needSignatureStr="";
	var paramsSortedString=querystring.stringify(sortedParam,'&&',"&&",{
			encodeURIComponent:function(s){
				return s;
			}
		})+secretKey;
	needSignatureStr=paramsSortedString.replace(/&&/g,"");
	md5er.update(needSignatureStr,"UTF-8");
	return md5er.digest('hex');
};
//请求参数
var post_data = {
	// 1.设置公有有参数
	secretId:secretId,
	businessId:businessId,
	version:"v2",
	timestamp:new Date().getTime(),
	nonce:noncer(),
	// 2.设置私有参数
	dataId:"myid",
	url:"www.xxxx.com/xxx",
	callback:"mycallback"
};
var signature=genSignature(secretKey,post_data);
post_data.signature=signature;
var content = querystring.stringify(post_data,null,null,null);
var options = {
    hostname: host,
    port: port,
    path: path,
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Content-Length': Buffer.byteLength(content)
    }
};

var req = http.request(options, function (res) {
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
		var data = JSON.parse(chunk);
		var code=data.code;
		var msg=data.msg;
		if(code==200){
			var result=data.result;
			if(result){
				console.log("推送成功");
			}else{
				console.log("推送失败");
			}
		}else{
			 console.log('ERROR:code=' + code+',msg='+msg);
		}

    });
});
//设置超时
req.setTimeout(1000,function(){
	console.log('request timeout!');
	req.abort();
});
req.on('error', function (e) {
    console.log('request ERROR: ' + e.message);
});
req.write(content);
req.end();
```
### `10.6`响应示例
输出结果：

```json
{
    "code": 200,
    "msg": "ok",
    "result": true
}
```
## `11`直播流检测结果获取
*******************

### `11.1`接口地址
[https://api.aq.163.com/v2/livevideo/callback/results](https://api.aq.163.com/v2/livevideo/callback/results)
### `11.2`接口描述
该接口用于获取直播流检测结果，检测结果包含截图证据信息及违规分类信息等。接口对请求频率做了限制，请求频率过快服务器会拒绝处理，建议每30秒获取一次。

### `11.3`请求参数
该接口参数与请求公共参数一致，详细见 [请求公共参数](#2_1)

### `11.4`响应结果
响应字段如下，响应通用字段已省略，详细见 [响应通用字段](#2_2) ：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| result | json数组 | 检测结果数组 |


result 数据结构

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| callback | String | 产品提交直播流信息时带的 callback 字段数据，用于标识直播流，产品根据业务情况自行设计 |
| evidence | json对象 | 证据信息 |
| labels | json数组 | 检测结果数组，如为空，则表示内容正常，如不为空，则表示检测到违规信息 |

evidence数据结构：

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| beginTime | Number | 证据开始时间 |
| endTime | Number | 证据结束时间 |
| type | Number | 1：图片，2：视频 |
| url | String | 证据信息 |

labels数据结构

| 参数名称 | 类型 | 描述 |
|----------|------|------|
| label | Number | 分类信息，100：色情，200：广告，300：暴恐，400：违禁，500：政治敏感 |
| level | Number | 级别信息，分为1：不确定，2：确定 |
| rate | Number | 分数 |

### `11.5`请求示例

```java
/*
 * @(#) LiveVideoCallbackAPIDemo.java 2016年8月1日
 *
 * Copyright 2010 NetEase.com, Inc. All rights reserved.
 */
package com.netease.is.antispam.demo.v2;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.http.Consts;
import org.apache.http.client.HttpClient;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.netease.is.antispam.demo.utils.HttpClient4Utils;
import com.netease.is.antispam.demo.utils.SignatureUtils;

/**
 * 调用易盾反垃圾云服务直播离线结果获取接口API示例，该示例依赖以下jar包：
 * 1. httpclient，用于发送http请求
 * 2. commons-codec，使用md5算法生成签名信息，详细见SignatureUtils.java
 * 3. gson，用于做json解析
 *
 * @author hzgaomin
 * @version 2016年8月1日
 */
public class LiveVideoCallbackAPIDemo {
    /** 产品密钥ID，产品标识 */
    private final static String SECRETID = "your_secret_id";
    /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
    private final static String SECRETKEY = "your_secret_key";
    /** 业务ID，易盾根据产品业务特点分配 */
    private final static String BUSINESSID = "your_business_id";
    /** 易盾反垃圾云服务直播离线结果获取接口地址 */
    private final static String API_URL = "https://api.aq.163.com/v2/livevideo/callback/results";
    /** 实例化HttpClient，发送http请求使用，可根据需要自行调参 */
    private static HttpClient httpClient = HttpClient4Utils.createHttpClient(100, 20, 10000, 1000, 1000);

    /**
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        // 1.设置公共参数
        params.put("secretId", SECRETID);
        params.put("businessId", BUSINESSID);
        params.put("version", "v2");
        params.put("timestamp", String.valueOf(System.currentTimeMillis()));
        params.put("nonce", String.valueOf(new Random().nextInt()));

        // 2.生成签名信息
        String signature = SignatureUtils.genSignature(SECRETKEY, params);
        params.put("signature", signature);

        // 3.发送HTTP请求，这里使用的是HttpClient工具包，产品可自行选择自己熟悉的工具包发送请求
        String response = HttpClient4Utils.sendPost(httpClient, API_URL, params, Consts.UTF_8);

        // 4.解析接口返回值
        JsonObject resultObject = new JsonParser().parse(response).getAsJsonObject();
        int code = resultObject.get("code").getAsInt();
        String msg = resultObject.get("msg").getAsString();
        if (code == 200) {
            JsonArray resultArray = resultObject.getAsJsonArray("result");
            for (JsonElement jsonElement : resultArray) {
                JsonObject jObject = jsonElement.getAsJsonObject();
                String callback = jObject.get("callback").getAsString();
                JsonObject evidenceObjec = jObject.get("evidence").getAsJsonObject();
                JsonArray labelArray = jObject.get("labels").getAsJsonArray();
                if (labelArray.size() == 0) {// 检测正常
                    System.out.println(String.format("正常, callback=%s, 证据信息：%s", callback, evidenceObjec));
                } else {
                    for (JsonElement labelElement : labelArray) {
                        JsonObject lObject = labelElement.getAsJsonObject();
                        int label = lObject.get("label").getAsInt();
                        int level = lObject.get("level").getAsInt();
                        double rate = lObject.get("rate").getAsDouble();
                        System.out.println(String.format("异常, callback=%s, 分类：%s, 证据信息：%s", callback, lObject, evidenceObjec));
                    }
                }
            }
        } else {
            System.out.println(String.format("ERROR: code=%s, msg=%s", code, msg));
        }
    }
}

```
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""易盾视频直播流离线检测结果获取接口python示例代码
接口文档: http://dun.163.com/api.html
python版本：python2.7
运行:
    1. 修改 SECRET_ID,SECRET_KEY,BUSINESS_ID 为对应申请到的值
    2. $ python callback.py
"""
__author__ = 'yidun-dev'
__date__ = '2016/3/10'
__version__ = '0.1-dev'

import hashlib
import time
import random
import urllib
import urllib2
import json

class LiveVideoCallbackAPIDemo(object):
    """视频直播流离线检测结果获取接口示例代码"""
    API_URL = "https://api.aq.163.com/v2/livevideo/callback/results"
    VERSION = "v2"

    def __init__(self, secret_id, secret_key, business_id):
        """
        Args:
            secret_id (str) 产品密钥ID，产品标识
            secret_key (str) 产品私有密钥，服务端生成签名信息使用
            business_id (str) 业务ID，易盾根据产品业务特点分配
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.business_id = business_id

    def gen_signature(self, params=None):
        """生成签名信息
        Args:
            params (object) 请求参数
        Returns:
            参数签名md5值
        """
        buff = ""
        for k in sorted(params.keys()):
            buff += str(k)+ str(params[k])
        buff += self.secret_key
        return hashlib.md5(buff).hexdigest()

    def check(self):
        """请求易盾接口
        Returns:
            请求结果，json格式
        """
        params = {}
        params["secretId"] = self.secret_id
        params["businessId"] = self.business_id
        params["version"] = self.VERSION
        params["timestamp"] = int(time.time() * 1000)
        params["nonce"] = int(random.random()*100000000)
        params["signature"] = self.gen_signature(params)

        try:
            params = urllib.urlencode(params)
            request = urllib2.Request(self.API_URL, params)
            content = urllib2.urlopen(request, timeout=10).read()
            return json.loads(content)
        except Exception, ex:
            print "调用API接口失败:", str(ex)

if __name__ == "__main__":
    """示例代码入口"""
    SECRET_ID = "your_secret_id" # 产品密钥ID，产品标识
    SECRET_KEY = "your_secret_key" # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "your_business_id" # 业务ID，易盾根据产品业务特点分配
    api = LiveVideoCallbackAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)

    ret = api.check()

    if ret["code"] == 200:
        for result in ret["result"]:
            labels = result["labels"]
            if labels: # 返回labels不为空表示有问题
                print "evidence = %s" % result["evidence"]
                for label in labels:
                    print "label = %s, level = %s, rate = %s" % (label["label"], label["level"], label["rate"])
    else:
        print "ERROR: ret.code=%s, ret.msg=%s" % (ret["code"], ret["msg"])
```
```PHP
<?php
/** 产品密钥ID，产品标识 */
define("SECRETID", "your_secret_id");
/** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
define("SECRETKEY", "your_secret_key");
/** 业务ID，易盾根据产品业务特点分配 */
define("BUSINESSID", "your_business_id");
/** 易盾反垃圾云服务直播视频检测结果获取接口地址 */
define("API_URL", "https://api.aq.163.com/v2/livevideo/callback/results");
/** api version */
define("VERSION", "v2");
/** API timeout*/
define("API_TIMEOUT", 10);
/** php内部使用的字符串编码 */
define("INTERNAL_STRING_CHARSET", "auto");
/**
 * 计算参数签名
 * $params 请求参数
 * $secretKey secretKey
 */
function gen_signature($secretKey, $params){
	ksort($params);
	$buff="";
	foreach($params as $key=>$value){
		$buff .=$key;
		$buff .=$value;
	}
	$buff .= $secretKey;
	return md5($buff);
}
/**
 * 将输入数据的编码统一转换成utf8
 * @params 输入的参数
 */
function toUtf8($params){
	$utf8s = array();
    foreach ($params as $key => $value) {
    	$utf8s[$key] = is_string($value) ? mb_convert_encoding($value, "utf8", INTERNAL_STRING_CHARSET) : $value;
    }
    return $utf8s;
}
/**
 * 反垃圾请求接口简单封装
 * $params 请求参数
 */
function check(){
    $params = array();
	$params["secretId"] = SECRETID;
	$params["businessId"] = BUSINESSID;
	$params["version"] = VERSION;
	$params["timestamp"] = sprintf("%d", round(microtime(true)*1000));// time in milliseconds
	$params["nonce"] = sprintf("%d", rand()); // random int
	$params = toUtf8($params);
	$params["signature"] = gen_signature(SECRETKEY, $params);
	// var_dump($params);
	$options = array(
	    'http' => array(
	        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
	        'method'  => 'POST',
	        'timeout' => API_TIMEOUT, // read timeout in seconds
	        'content' => http_build_query($params),
	    ),
	);
	var_dump($params);
	$context  = stream_context_create($options);
	$result = file_get_contents(API_URL, false, $context);
	return json_decode($result, true);
}
// 简单测试
function main(){
    echo "mb_internal_encoding=".mb_internal_encoding()."\n";
	$ret = check();
	var_dump($ret);
	if ($ret["code"] == 200) {
		$result = $ret["result"];
		foreach($result as $index => $value){
			$labels = $value["labels"];
			if(!empty($labels)){// labels不为空说明发现有问题
				echo "evidence = ".json_encode($value["evidence"])."\n";
				foreach ($labels as $i => $label) {
					echo "label = ".$label["label"].", level = ".$label["level"].", rate = ".$label["rate"]."\n";
				}
			}
		}
    }else{
    	// error handler
    }
}
main();
?>
```
```c#
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Com.Netease.Is.Antispam.Demo
{
    class LiveVideoCallbackApiDemo
    {
        public static void liveVideotCallBack()
        {
            /** 产品密钥ID，产品标识 */
            String secretId = "your_secret_id";
            /** 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露 */
            String secretKey = "your_secret_key";
            /** 业务ID，易盾根据产品业务特点分配 */
            String businessId = "your_business_id";
            /** 易盾反垃圾云服务直播离线结果获取接口地址 */
            String apiUrl = "https://api.aq.163.com/v2/livevideo/callback/results";
            Dictionary<String, String> parameters = new Dictionary<String, String>();

            long curr = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            String time = curr.ToString();

            // 1.设置公共参数
            parameters.Add("secretId", secretId);
            parameters.Add("businessId", businessId);
            parameters.Add("version", "v2");
            parameters.Add("timestamp", time);
            parameters.Add("nonce", new Random().Next().ToString());

            // 2.生成签名信息
            String signature = Utils.genSignature(secretKey, parameters);
            parameters.Add("signature", signature);

            // 3.发送HTTP请求
            HttpClient client = Utils.makeHttpClient();
            String result = Utils.doPost(client, apiUrl, parameters, 10000);
            if(result != null)
            {
                JObject ret = JObject.Parse(result);
                int code = ret.GetValue("code").ToObject<Int32>();
                String msg = ret.GetValue("msg").ToObject<String>();
                if (code == 200)
                {
                    JArray array = (JArray)ret.SelectToken("result");
                    foreach (var item in array)
                    {
                        JObject tmp = (JObject)item;
                        String callback = tmp.GetValue("callback").ToObject<String>();
                        JObject evidenceObjec = (JObject)tmp.SelectToken("evidence");
                        JArray labels = (JArray)tmp.SelectToken("labels");
                        if (labels.Count == 0)
                        {
                            Console.WriteLine(String.Format("正常, callback={0}, 证据信息: {1}", callback, evidenceObjec.ToString()));
                        }
                        else
                        {
                            foreach (var labelObj in labels)
                            {
                                JObject tmp2 = (JObject)labelObj;
                                int label = tmp2.GetValue("label").ToObject<Int32>();
                                int level = tmp2.GetValue("level").ToObject<Int32>();
                                double rate = tmp2.GetValue("rate").ToObject<Double>();
                                Console.WriteLine(String.Format("异常, callback={0}, 分类：{1}, 证据信息：{2}", callback, label, evidenceObjec.ToString()));
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine(String.Format("ERROR: code={0}, msg={1}", code, msg));
                }
            }
            else
            {
                Console.WriteLine("Request failed!");
            }
        }
}
}
```
```js
var http = null;
var urlutil=require('url');
var querystring = require('querystring');
var crypto = require('crypto');
var md5er = crypto.createHash('md5');//MD5加密工具

//产品密钥ID，产品标识
var secretId="your_secret_id";
// 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
var secretKey="your_secret_key";
// 业务ID，易盾根据产品业务特点分配
var businessId="your_business_id";
// 易盾反垃圾云服务直播离线结果获取接口地址
var apiurl="https://api.aq.163.com/v2/livevideo/callback/results";
var urlObj=urlutil.parse(apiurl);
var protocol=urlObj.protocol;
var host=urlObj.hostname;
var path=urlObj.path;
var port=urlObj.port;
if(protocol=="https:"){
	http=require('https');
}else{
	console.log("ERROR:portocol parse error, and portocol must be https !");
	return;
}
//产生随机整数--工具方法
var noncer=function(){
	var range=function(start,end){
		var array=[];
		for(var i=start;i<end;++i){
			array.push(i);
		}
		return array;
	};
	var nonce = range(0,6).map(function(x){
		return Math.floor(Math.random()*10);
	}).join('');
	return nonce;
}

//生成签名算法--工具方法
var genSignature=function(secretKey,paramsJson){
	var sorter=function(paramsJson){
		var sortedJson={};
		var sortedKeys=Object.keys(paramsJson).sort();
		for(var i=0;i<sortedKeys.length;i++){
			sortedJson[sortedKeys[i]] = paramsJson[sortedKeys[i]]
		}
		return sortedJson;
	}
	var sortedParam=sorter(paramsJson);
	var needSignatureStr="";
	var paramsSortedString=querystring.stringify(sortedParam,'&&',"&&",{
			encodeURIComponent:function(s){
				return s;
			}
		})+secretKey;
	needSignatureStr=paramsSortedString.replace(/&&/g,"");
	md5er.update(needSignatureStr,"UTF-8");
	return md5er.digest('hex');
};
//请求参数
var post_data = {
	// 1.设置公有有参数
	secretId:secretId,
	businessId:businessId,
	version:"v2",
	timestamp:new Date().getTime(),
	nonce:noncer()
};
var signature=genSignature(secretKey,post_data);
post_data.signature=signature;
var content = querystring.stringify(post_data,null,null,null);
var options = {
    hostname: host,
    port: port,
    path: path,
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'Content-Length': Buffer.byteLength(content)
    }
};

var req = http.request(options, function (res) {
    res.setEncoding('utf8');
    var responseData = "";
    res.on('data', function (chunk) {
    	responseData+=chunk;
    });
    res.on("end",function(){
    	var data = JSON.parse(responseData);
		var code=data.code;
		var msg=data.msg;
		if(code==200){
			var result=data.result;
			if(result.length==0){
				console.log("无数据");
			}else{
				for(var i=0;i<result.length;i++){
					var obj=result[i];
					var callback=obj.callback;
					var evidence=obj.evidence;
					var labelsArray=obj.labels;
					if(labelsArray.length==0){
						console.log("正常，callback:"+callback+",证据信息："+JSON.stringify(evidence));
					}else{
						for(var k=0;k<labelsArray.length;k++){
							var labelObj=labelsArray[k];
							var label=labelObj.label;
							var level=labelObj.level;
							var rate=labelObj.rate;
							console.log("异常，callback:"+callback+",分类："+JSON.stringify(labelObj)+",证据信息："+JSON.stringify(evidence));
						}
					}
				}
			}
		}else{
			 console.log('ERROR:code=' + code+',msg='+msg);
		}
    });
});
//设置超时
req.setTimeout(1000,function(){
	console.log('request timeout!');
	req.abort();
});
req.on('error', function (e) {
    console.log('request ERROR: ' + e.message);
});
req.write(content);
req.end();
```
### `11.6`响应示例
输出结果：

```json
{
    "code": 200,
    "msg": "ok",
    "result": [
        {
            "callback": "40d7e2fba1894512902e92928540a647",
            "evidence": {
                "beginTime": 1469774975520,
                "endTime": 1469774975520,
                "type": 1,
                "url": "http://xxx.nos.netease.com/xxx.jpeg"
            },
            "labels": [
                {
                    "label": 100,
                    "level": 2,
                    "rate": 1
                }
            ]
        },
        {
            "callback": "40d7e2fba1894512902e92928540a647",
            "evidence": {
                "beginTime": 1469775156321,
                "endTime": 1469775156321,
                "type": 1,
                "url": "http://xxx.nos.netease.com/xxxx.jpeg"
            },
            "labels": []
        }
    ]
}
```

<!-- /@NOCOMPRESS -->
