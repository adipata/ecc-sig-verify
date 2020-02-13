package lu.pata.cert.crt.certificate.algorithmidentifier;

import java.util.Arrays;

/**
 * Description based on http://oid-info.com/get/1.2.840.10045.4.1
 */
public class SignatureAlgorithms{
    static private String[] oids={"1.2.840.10045.4.1","1.2.840.10045.4.3.2"};
    static private String[] oidsDesc={"ecdsa-with-SHA1","ecdsa-with-SHA256"};

    static public boolean supportOID(String oid){
        return Arrays.stream(oids).anyMatch(oid::equals);
    }
}
