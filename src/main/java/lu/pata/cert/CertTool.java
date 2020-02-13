package lu.pata.cert;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.util.Enumeration;

public class CertTool {
    static public void dumpSequenceObjects(ASN1Sequence seq){
        Enumeration secEnum = seq.getObjects();
        while (secEnum.hasMoreElements()) {
            ASN1Primitive seqObj = (ASN1Primitive) secEnum.nextElement();
            System.out.println(seqObj.getClass());
        }
    }
}
