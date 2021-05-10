package com.shanks.encrypt;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.symmetric.AES;
import com.shanks.encrypt.res.HttpEncryptRes;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

/**
 * FileName    :
 * Description :
 *
 * @author : Shanks
 * @version : 1.0
 * Create Date : 2020/7/25 16:45
 **/
@Slf4j
public class EncryptUtilsTest {


    @Test
    public void test1() throws Exception {
        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOIy47hPSy39-sTVn4LK7iZVoUhWH6RtYGQk6dYOtbp7eT0g3op0bp26NKgxnKs8oy9jcTYYAppiZDKp_capbaOQiQfWoBdohQT-M9N5Qfh8SKmhKfvbILZntN6uTmMy6mj2R_Ro1rd1SkhiKiDJ44OvtL0PyqE-B1yXfvu-SewQIDAQAB";
        String priKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAI4jLjuE9LLf36xNWfgsruJlWhSFYfpG1gZCTp1g61unt5PSDeinRunbo0qDGcqzyjL2NxNhgCmmJkMqn9xqlto5CJB9agF2iFBP4z03lB-HxIqaEp-9sgtme03q5OYzLqaPZH9GjWt3VKSGIqIMnjg6-0vQ_KoT4HXJd--75J7BAgMBAAECgYA5rEy2GdywN-aqIzi-WmMbucQzT2vSAawWHhGICit1pTf34uOB414Cxfwb39Y3SXxh8UWnt4gpXiFoX4M-DIHorvp1ICQrNg0WkFfPt9DacNpmHKNeXq34pYg9bHaYYK7FEiwOqYWk2M6wW_sZVTGFW4YOoXalp6DTgguGb3WngQJBAMjIAT4nbTh1FrchnEWxImOKOyZCOiUuZRwhZUfjekarPrudarYZ2ygAs8AqCZuJBHG42HiK7AAKU3fLQrobbRcCQQC1OlvaR7Tz5_mLXwxO6oO_mUfWTYSwu34N9mBGFgPh-Gn5gSRgMrt0G3oRBy1jHZKLOqa4M3IArJepyisNh6nnAkEAjoa7qx1dwOgNOe6X-jjlyndDycLVd7NZfwCN3twx3pyNKa1zJNVx5xGoh87PhyNajkfDEr67DMRHwA__zBDP_QJAaB5DL0ELQSYBRIUy-RPa5XUWxJR8q1zMqxDldt6nFGg32lTLpUkAUVCH7MiG1u7ihoMHzcQgtypxZ-bynS9X-QJBAKJpOynfp85AzrYi3C8bua7G5fj9B0LD0LBbUvK-nruiKjBiIy_oL-ZtWiKi9ofMpKlzIpedY8R3LFNXMcUNSJ0";

        String reqData = "{\"name1\":\"123\"}";

        // 随机aesKey
        String aesKey = RandomUtil.randomString(32);
        ;
        // rsa(aesKey)
        RSA rsa = new RSA(priKey, pubKey);
        String key = Base64.encodeUrlSafe(rsa.encrypt(aesKey, KeyType.PublicKey));
        // aes(data)
        AES aes = SecureUtil.aes(aesKey.getBytes());
        String data = Base64.encodeUrlSafe(aes.encrypt(reqData));

        // 生成签名
        Long timestamp = System.currentTimeMillis();
        String nonce = RandomUtil.randomString(6);
        String sign = SecureUtil.sha256(StringUtils.join(key, data, nonce, timestamp));
        log.info("key:{}", key);
        log.info("data:{}", data);
        log.info("nonce:{}", nonce);
        log.info("timestamp:{}", timestamp);
        log.info("sign:{}", sign);
    }


    public static HttpEncryptRes clientReq() {
        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOIy47hPSy39-sTVn4LK7iZVoUhWH6RtYGQk6dYOtbp7eT0g3op0bp26NKgxnKs8oy9jcTYYAppiZDKp_capbaOQiQfWoBdohQT-M9N5Qfh8SKmhKfvbILZntN6uTmMy6mj2R_Ro1rd1SkhiKiDJ44OvtL0PyqE-B1yXfvu-SewQIDAQAB";
        String reqData = "{\"name\":\"123\"}";

        // 随机aesKey
        String aesKey = RandomUtil.randomString(32);

        // rsa(aesKey)
        RSA rsa = new RSA(null, pubKey);
        String key = Base64.encodeUrlSafe(rsa.encrypt(aesKey, KeyType.PublicKey));
        // aes(data)
        AES aes = SecureUtil.aes(aesKey.getBytes());
        String data = Base64.encodeUrlSafe(aes.encrypt(reqData));

        // 生成签名
        Long timestamp = System.currentTimeMillis();
        String nonce = RandomUtil.randomString(6);
        String sign = SecureUtil.sha256(StringUtils.join(key, data, nonce, timestamp));
        log.info("key:{}", key);
        log.info("data:{}", data);
        log.info("nonce:{}", nonce);
        log.info("timestamp:{}", timestamp);
        log.info("sign:{}", sign);

        HttpEncryptRes res = new HttpEncryptRes();
        res.setKey(key);
        res.setData(data);
        res.setNonce(nonce);
        res.setTimestamp(timestamp);
        return res;
    }


    @Test
    public void test() throws Exception {

        // 客户端公钥
        String cpu = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzScIV2lpf671p3m/8yda" +
                "t02xuy1XeLx5h/EemIy1YgxseeM7WCmiJSXwJiVpSJIjK2wMNFHRqvI1lZTP4/ir" +
                "/wrJxFczZFpG2VikrnlPfuj+O3SnTgFg1Ui6QTtJlwULGWZA1aosPU4D4dUxyuUM" +
                "uzW8hV9/a1E6gbeljvD95VLbmv8tyIq3RpGjB+l7o0JJMFGexK/+lnCkbxgKqP3S" +
                "9ny5qtjKF5XTwc70Jhb9i3VBKe0lPKjnYxbRSmVuXXY4geYOJL9Q/klDONQ1X5hk" +
                "PuGP0N2Sx2qtC82299QnObqPpQAL8oK2dRMym3HfqkxFerDQ95L8p5wfcIHi9fEz" +
                "ZQIDAQAB";

        // 服务器公钥
        String spu = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsPPXjTCeSCG46O2apMFu" +
                "joqbVbUREplbVuBpg7J5cMTaXJY1fY2PCOmgHVBJM0q8BW17hf1/18ndfF2oQwh6" +
                "YuWDEfldMfyH3Rou2kedmCd4AOTp89+XClDymbTLUtkKu7WpZxj1xLV6lNiZsnpZ" +
                "BYf4Qn2ucjB2+AbMt34gTC1aVTCEV9VmNTPom6ydz+KXvH27GEUSWzdAjS8z+MRK" +
                "vfRvW6dv6Jx0eugJQ0QD16s4WlxTtETENPxTKp71sx18Pq09755qOnxpMS0rMeOD" +
                "w1iGsm6Gg07L+D+AyqpYR5SVWBuqOogcZ2E2PeUx6GAvWWTb1Lsz073DD3QRJMi1" +
                "iwIDAQAB";

        // 客户端私钥
        String cpr = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNJwhXaWl/rvWn" +
                "eb/zJ1q3TbG7LVd4vHmH8R6YjLViDGx54ztYKaIlJfAmJWlIkiMrbAw0UdGq8jWV" +
                "lM/j+Kv/CsnEVzNkWkbZWKSueU9+6P47dKdOAWDVSLpBO0mXBQsZZkDVqiw9TgPh" +
                "1THK5Qy7NbyFX39rUTqBt6WO8P3lUtua/y3IirdGkaMH6XujQkkwUZ7Er/6WcKRv" +
                "GAqo/dL2fLmq2MoXldPBzvQmFv2LdUEp7SU8qOdjFtFKZW5ddjiB5g4kv1D+SUM4" +
                "1DVfmGQ+4Y/Q3ZLHaq0Lzbb31Cc5uo+lAAvygrZ1EzKbcd+qTEV6sND3kvynnB9w" +
                "geL18TNlAgMBAAECggEAdK7drLH04j2F1RKHXWoly5oyG27nkHFKgkpfB48IX1MH" +
                "o6/dggB0C8LvOxMONcuAm2Lh8iQTJ7KJTaGNOHGoie/94GFkhpBeOaKUT/QJhfpJ" +
                "F1H7En/wLn8mCJILAg1JSdIB0ETw0pF73cefgXITcqtWpVkypLxXlY35aTqiffpE" +
                "4kh853fidEevFUy1NFINWwng3djM/5ahMA8SOJ2Q2US5CP6KSOkRDYiKrViicvKT" +
                "0hdk8ndNV6IfGg5/pFJmp63dYN+/1vr2+tKLZrOzpQD/DhqoezAutSBsZjRotgWC" +
                "dgJkU1hL4LdncCtsCEi9EQ0LIE/ZAMwrWh4VUdFsgQKBgQDl3CmbauxZfGIXEYqd" +
                "lQQTZdK1ckYvmgYj+TX6Jmf4R7JTUgmloyuSESG3D5zc4JTqnJG0wl2n5Vp9QiPD" +
                "oUQbrxNST6/rWGheH8j8JK8fccG70sf3uM+9fsaY7uRxlQgLpZWnHZ55a9k+8Zjx" +
                "u8HAEkJoG5xSHEF+sGBx+QHXYQKBgQDke5FYUZgsDTAQ8fS6UmenMVVsWV9s5XdV" +
                "IFeH2vSs/7J2kh4bd+3TIIJTosPVxPJTnzLNSMSaywmJ6NT1GgnAEMLOhYP7Lx0b" +
                "GDILzedSoNmAK1+FRfEmHTDA7gB7QbBEOdd0Er8Im0pWZiGQCwmYUQ8k5G6K8px/" +
                "JqFy21UOhQKBgDizFDhYKbDxM6kJFK5GYdj/FvjXFWUMk1MwWBY6fw8JcH2JEQQg" +
                "udCwFSb43PLHGzS8Jlz2TO/rbWTUecn577j8eMGnEnf1ONlu8b7wtZoGD4nrNpRu" +
                "rB/MM+TpmMRDxNZKpB2y+rJs3gvewKFwdRyR5HuVw/ulKKq9iyzSBZhBAoGAMUaN" +
                "BBUk0mtNsHneI8jd3er/10w3Dk82uz8sYXpRRnYm0PeWUqo8uknKkasKvTGqaWpu" +
                "FGPbMt8TAZEbTHj/HVMAEHYvDp8MkelX8b/IYcOa5M913FJHPccR2qn5pJt4Hl6z" +
                "Hq9kT8Dd+WAxYNVgjl78+yHgzUqhgbKdIx42a9kCgYEAm+bxxfJZTsCIr3OkiGkh" +
                "/hjDssrggq40u97bQi/n9tEF+fx3z5/I3hpyBi6yUOYrX+Er3CJ3bUQwJC8M6ExC" +
                "DBrG/6tdvKTA13OvZxhO+WrvoKGgOVk7rm13q7x1dbr2HSs7Ct4CqP9HM78QxX3M" +
                "YLnfgLBdsM0KfV8T7LcJSvk=";

        // 服务器私钥
        String spr = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCw89eNMJ5IIbjo" +
                "7ZqkwW6OiptVtRESmVtW4GmDsnlwxNpcljV9jY8I6aAdUEkzSrwFbXuF/X/Xyd18" +
                "XahDCHpi5YMR+V0x/IfdGi7aR52YJ3gA5Onz35cKUPKZtMtS2Qq7talnGPXEtXqU" +
                "2JmyelkFh/hCfa5yMHb4Bsy3fiBMLVpVMIRX1WY1M+ibrJ3P4pe8fbsYRRJbN0CN" +
                "LzP4xEq99G9bp2/onHR66AlDRAPXqzhaXFO0RMQ0/FMqnvWzHXw+rT3vnmo6fGkx" +
                "LSsx44PDWIayboaDTsv4P4DKqlhHlJVYG6o6iBxnYTY95THoYC9ZZNvUuzPTvcMP" +
                "dBEkyLWLAgMBAAECggEASvVgkCzSQBgY7oMIiVZvcO6CUtI7Azf3m1vBFsrZ6s1Y" +
                "+vOegSsgNlRRQVmrSJEWCO6R7vat20lmC7LY/lxvC8nRtiF+OxiQrTbUNh80QSon" +
                "Canu+SH0J6iWvEn7/4J1q4KO2l+WbNe7r6X5pcNyRoeMwQ3ggfrJytOGkQxavimb" +
                "nVHVFzcNCjMXqaTd8bDbdCv+WUOCoNCbPpXkLpMrwRnFL9WdjVomx9+hXtds9OgC" +
                "9iKeROA/y6DGfqixq2V/R6JO0C/t1oYvR/FFI7e/eChnvFFqhp7fkf6gQYg+/8gr" +
                "iLLU1MlxazLu4soJ1S+kI6ix2hXgWGGvsZLvCYkTQQKBgQDfQnAKb58PpOLUJ4S8" +
                "uxWUcMOoO2MN95GKvB9PXVQ07N1dZbWes31nSGjC5OlEx5cQCSjJo3/ZivNM+UBz" +
                "i3WZ7rARR5eoxl4AoA2Z8iMkgVzNKVe+3M+3EYFtcUPCubdnhDELOmgxPBeCQW+1" +
                "yQWnWFm0UVRs4/uIF1IDLAFkWwKBgQDK5vTBv9JqGeowywPT9qiPW18EtLKx2y4X" +
                "ftXGD+h0ywIsFDOIjb14n9t1FDoRcTmKpq+ij9CMM/YVJ6hP6rFSAhLENkjomlAc" +
                "2/6jOKlO3P5TfJMJma82+Zt5pe6vTLIothK84X08VBkNEN3AvFKIkFV7ZqI7TmMC" +
                "2wsf/Fr6kQKBgQCvOejP+A2ibKpvEtk2e6uTRvH5nyq+cplzhvUYCEsoAuQ3ArYK" +
                "ahu5rXYzyRBgoDorJtUxdTbKGimdN1/jkAhsGY9s8IDSwWZUHUqvkgENDM82YwVw" +
                "UsRgjcfEiwpA0hxljbYkduICCoT1AcDYr37Veh1lzhNyJ3lqtcrznF03UwKBgFA3" +
                "mxB2fAPClxoPSUYlwGJc52X+4p76XnCfjnitlWOHVyaCHhWgpAXqfWL+Si7XKr6s" +
                "Q8frP7IOYP3gHeTqjowzkaPNKmn7iCzAtR1mq1koecwb9i3XerQrXtJrTcA0fEMo" +
                "KKRQKakOPpEx19n5GlAvb/xHiWAVD4PzgaR1qqphAoGBAJXxrFFCVlwXg38jn+dj" +
                "vJehyZsx5nSljSQeIgaCOaLZ9Hs3egZN3Ym8hS8yVIip3gIXp4NbU4PXWlHN+MaZ" +
                "NV/sXu8jgK2ldVbZGcv4MCz5/ozltjutom5xNZONUY5WtFredAKW4uJGIjcm7Ru/" +
                "1xTis4iyhmELkoXRQgjeI6Ec";

        RSA service = new RSA(spr, spu);
        RSA clint = new RSA(cpr, cpu);

//        String data = "123456789101112131415161718192021222323842934928349823042034234";
//        // step 1 客户端拿服务器的公钥加密
//        String enStr = Base64.encodeBase64String(service.encrypt(data, KeyType.PublicKey));
//        log.info("encode:{}", enStr);
//
//        //org.apache.commons.codec.binary.Base64.decodeBase64()
//        // step 2 服务器拿
//        String deStr = new String(service.decrypt(new String(Base64.decodeBase64(enStr)), KeyType.PrivateKey));
//        log.info("deStr:{}", deStr);

    }


    @Test
    public void RsaTest() {
        String PRIVATE_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIL7pbQ+5KKGYRhw7jE31hmA"
                + "f8Q60ybd+xZuRmuO5kOFBRqXGxKTQ9TfQI+aMW+0lw/kibKzaD/EKV91107xE384qOy6IcuBfaR5lv39OcoqNZ"
                + "5l+Dah5ABGnVkBP9fKOFhPgghBknTRo0/rZFGI6Q1UHXb+4atP++LNFlDymJcPAgMBAAECgYBammGb1alndta"
                + "xBmTtLLdveoBmp14p04D8mhkiC33iFKBcLUvvxGg2Vpuc+cbagyu/NZG+R/WDrlgEDUp6861M5BeFN0L9O4hz"
                + "GAEn8xyTE96f8sh4VlRmBOvVdwZqRO+ilkOM96+KL88A9RKdp8V2tna7TM6oI3LHDyf/JBoXaQJBAMcVN7fKlYP"
                + "Skzfh/yZzW2fmC0ZNg/qaW8Oa/wfDxlWjgnS0p/EKWZ8BxjR/d199L3i/KMaGdfpaWbYZLvYENqUCQQCobjsuCW"
                + "nlZhcWajjzpsSuy8/bICVEpUax1fUZ58Mq69CQXfaZemD9Ar4omzuEAAs2/uee3kt3AvCBaeq05NyjAkBme8SwB0iK"
                + "kLcaeGuJlq7CQIkjSrobIqUEf+CzVZPe+AorG+isS+Cw2w/2bHu+G0p5xSYvdH59P0+ZT0N+f9LFAkA6v3Ae56OrI"
                + "wfMhrJksfeKbIaMjNLS9b8JynIaXg9iCiyOHmgkMl5gAbPoH/ULXqSKwzBw5mJ2GW1gBlyaSfV3AkA/RJC+adIjsRGg"
                + "JOkiRjSmPpGv3FOhl9fsBPjupZBEIuoMWOC8GXK/73DHxwmfNmN7C9+sIi4RBcjEeQ5F5FHZ";

        RSA rsa = new RSA(PRIVATE_KEY, null);

        String a = "2707F9FD4288CEF302C972058712F24A5F3EC62C5A14AD2FC59DAB93503AA0FA17113A020EE4EA35EB53F"
                + "75F36564BA1DABAA20F3B90FD39315C30E68FE8A1803B36C29029B23EB612C06ACF3A34BE815074F5EB5AA3A"
                + "C0C8832EC42DA725B4E1C38EF4EA1B85904F8B10B2D62EA782B813229F9090E6F7394E42E6F44494BB8";

        byte[] aByte = HexUtil.decodeHex(a);
        byte[] decrypt = rsa.decrypt(aByte, KeyType.PrivateKey);
        String decrypt1 = StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8);
        log.info("d:{}", decrypt1);

        String t1 = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" +
                "111111111111111111111111111111111111111111111123423423423333333333333333333333323444444444444444444444444444444444444444444444444444444444444442" +
                "2344444444444444444444444444444444444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "23444444444444444444444444444444444444444444444444444444" +
                "234444444444444444444444444444444444444444444444444444444444444411";
        String t2 = StrUtil.str(rsa.encrypt(HexUtil.decodeHex(t1), KeyType.PrivateKey), CharsetUtil.CHARSET_UTF_8);
        log.info("d:{}", t2);
    }


    @Test
    public void aliRsa() {

        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG2W+jZX6ZajsUtaIQ5rZ58B78Wq504TBr6PFGeUxe6rvDon4F8ERMmTDipcDaXp8dZQvzEowtEwtSHRgEFUgtuiWEk9wLAIJdjCfr3utipnXQSmZNuhKx0Qxj4XgW0UoBlpAvYuuiaK313JjS4uLNiFqEg2Mhr44Y/1XZ09J3BwIDAQAB";
        String priKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIbZb6NlfplqOxS1ohDmtnnwHvxarnThMGvo8UZ5TF7qu8OifgXwREyZMOKlwNpenx1lC/MSjC0TC1IdGAQVSC26JYST3AsAgl2MJ+ve62KmddBKZk26ErHRDGPheBbRSgGWkC9i66JorfXcmNLi4s2IWoSDYyGvjhj/VdnT0ncHAgMBAAECgYA7HGVLgtoT9fUgBt6b+gZTPWbXyAhhQ7UuGFZrRhCsKslT4I7Nm5zU1vIO6Am5r3CgOgMa8i5wM8DqpcY5Q/r3J5GYlaA++ufnewB5MYRwFKtyiFFd9+zfY2PO07uxJP/rZ8ucM5ZP/7ee5SY3hAYfkTp79y8R8gwBQ9Sd9lk5QQJBAPOe5UwTxTYco8dN6oeHj6rylgUUN/2Gy4vBSJEntQQ9a+DQ05mbXI4AB64pPSvEG/wLQBaSB/Vh+gLvI5rS6eMCQQCNs5q5jX05wuEqgrWvhlBe28atXkpoZlYMzcKiRjcp7f+BgE2bYX4wuqHb+te1kpP4AnFATiHF4c7bssL0/teNAkAaenOrkB6IIha+674I2vgHeXRKuwbW3Fa1Kt3LQQiQnGhkN+43rMYjfOdYy4ylfBwaidJ+YYLR7cMxnHI/OptHAkBp0yhKSxCqgpAGX3ewjm6XaSsHbtPDBCpfhYtGBYpNFiErZdaPpE/JtJgM4VkXkVBQeAJ8M92lGu6RxP80WN5BAkEA5TkmwjhdZ4OU25EtBv/zZT9IBgHw0VshjeNf17856+II11g4uUfIVb+9HFm4Xta1Mxen5ss4sXAhS50FUYZbPg==";
        RSA rsa = new RSA(priKey, pubKey);
        String desKey = new String(rsa.decrypt(HexUtil.decodeHex("111"), KeyType.PrivateKey));
        log.info(desKey);
    }

}
