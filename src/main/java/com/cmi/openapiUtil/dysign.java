package com.cmi.openapiUtil;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;

public class dysign {

    public final static String SEPARATOR = "&";
    public final static String URL_ENCODING = "UTF-8";
    public static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    public static final String UTF8 = "UTF-8";

    public static String buildStringToSign(Map<String, String> toSignParams)
            throws Exception {
        if (null == toSignParams || toSignParams.isEmpty()) {
            return "";
        }

        Map<String, String> queries = toSignParams;
        String[] sortedKeys = queries.keySet().toArray(new String[] {});
        Arrays.sort(sortedKeys);
        StringBuilder canonicalizedQueryString = new StringBuilder();

        for (String key : sortedKeys) {

            canonicalizedQueryString.append(SEPARATOR)
                    .append(percentEncode(key)).append("=")
                    .append(percentEncode(queries.get(key)));
        }

        StringBuilder stringToSign = new StringBuilder();
        stringToSign.append(percentEncode(
                canonicalizedQueryString.toString().substring(1)));

        return stringToSign.toString();
    }

    /**
     * Get signature according to signedParams and secret
     * ref : com.aliyun.openapiutil version 0.1.14
     *
     * @param signedParams params which need to be signed
     * @param secret       AccessKeySecret
     * @return the signature
     */
    public static SignResult GetHmacsha1Signature(java.util.Map<String, String> toSignParams, String secret)
            throws Exception {

        SignResult result = new SignResult();

        if (null == toSignParams || StringUtils.isEmpty(secret)) {
            result.Signature = secret;
            return result;
        }

        String stringToSign = buildStringToSign(toSignParams);

        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(new SecretKeySpec((secret + SEPARATOR).getBytes(URL_ENCODING), HMAC_SHA1_ALGORITHM));
        byte[] signedData = mac.doFinal(stringToSign.getBytes(URL_ENCODING));

        result.StringToSign = stringToSign;
        result.Signature = Base64.encodeBase64String(signedData);

        return result;
    }

    public static String percentEncode(String value) throws UnsupportedEncodingException {
        return value != null ? URLEncoder.encode(value, URL_ENCODING).replace("+", "%20")
                .replace("*", "%2A").replace("%7E", "~") : null;
    }

}
