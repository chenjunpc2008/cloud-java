package com.cmi.openapiUtil;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class dysign_Test {

    @Test
    public void testNullSignedParamsReturnsSecret() throws Exception {
        String secret = "testSecret";

        SignResult result = dysign.GetHmacsha1Signature(null, secret);

        assertEquals(secret, result.Signature);
    }

    @Test
    public void testEmptySecretReturnsEmpty() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("key", "value");

        SignResult result = dysign.GetHmacsha1Signature(params, "");

        assertEquals("", result.Signature);
    }

    @Test
    public void testParamsSortedCorrectly() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("zKey", "zValue");
        params.put("aKey", "aValue");

        SignResult result1 = dysign.GetHmacsha1Signature(params, "secret");

        Map<String, String> orderedParams = new HashMap<>();
        orderedParams.put("aKey", "aValue");
        orderedParams.put("zKey", "zValue");

        SignResult result2 = dysign.GetHmacsha1Signature(orderedParams, "secret");

        assertEquals(result1.StringToSign, result2.StringToSign);
        assertEquals(result1.Signature, result2.Signature);
    }

    @Test
    public void testFullSignatureGeneration_1() throws Exception {
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

        String secret = "duh04756302dGYUEH937GFFUJE63468";

        // 预期签名
        String expected_StrToSign = "AccessKeyId%3Dacek-001%26CustomerId%3D10010%26FreezeStatus%3DACTIVE%26"
                + "Method%3DsmsRouteCreditControl%26SignatureMethod%3DHMAC-SHA1%26"
                + "SignatureNonce%3Dedb2b34af0af9a6d14deaf7c1a5315eb%26"
                + "SignatureVersion%3D1.0%26Timestamp%3D2023-01-01T14%253A21%253A46Z%26" + "Version%3D2023-07-11";
        String expected_Signature = "TgEiEEyOK6T/G4dQVOkmD0w7cTs=";

        SignResult actualRes = dysign.GetHmacsha1Signature(params, secret);

        assertEquals(expected_StrToSign, actualRes.StringToSign);
        assertEquals(expected_Signature, actualRes.Signature);
    }

}