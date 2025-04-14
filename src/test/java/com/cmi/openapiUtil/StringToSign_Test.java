package com.cmi.openapiUtil;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class StringToSign_Test {

    @Test
    public void test_buildStringToSign_1() throws Exception {
        Map<String, String> params = new HashMap<>();

        params.put("Method", "smsRouteCreditControl");
        params.put("AccessKeyId", "acek-001");
        params.put("Timestamp", "2023-01-01T14:21:46Z");
        params.put("Version", "2023-07-11");
        params.put("SignatureNonce", "edb2b34af0af9a6d14deaf7c1a5315eb");
        params.put("SignatureMethod", "HMAC-SHA1");
        params.put("SignatureVersion", "1.0");
        params.put("CustomerId", "10010");
        params.put("FreezeStatus", "ACTIVE");

        // 预期签名通过 Python 脚本计算得到（示例值，需替换为实际值）
        String expectedSignature = "AccessKeyId%3Dacek-001%26CustomerId%3D10010%26FreezeStatus%3DACTIVE%26Method%3DsmsRouteCreditControl%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3Dedb2b34af0af9a6d14deaf7c1a5315eb%26SignatureVersion%3D1.0%26Timestamp%3D2023-01-01T14%253A21%253A46Z%26Version%3D2023-07-11";
        String actualSignature = dysign.buildStringToSign(params);
        assertEquals(expectedSignature, actualSignature);
    }

}
