package lu.pata.cert.crt.certificate.tbscertificate;

import lu.pata.cert.CertException;
import org.bouncycastle.asn1.*;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class OidObject {
    private String oid;
    private String value;
    static private Map<String,String> oidDictionary=new HashMap<>();

    public OidObject(ASN1Primitive data) throws CertException {
        if(!(data instanceof ASN1Set)) throw new CertException("ASN1Set expected as input data OidObject.");
        ASN1Set oidSet=(ASN1Set)data;
        //TODO: More type checks needed below
        ASN1Sequence oidSeq=(ASN1Sequence)oidSet.getObjectAt(0); //Only one sequence expected
        Enumeration oidEnum=oidSeq.getObjects();
        oid=((ASN1ObjectIdentifier)oidEnum.nextElement()).getId();
        value=((ASN1String)oidEnum.nextElement()).getString();
    }

    public String getName(){
        return oidDictionary.get(oid);
    }

    public String getValue(){
        return value;
    }

    static {
        oidDictionary.put("2.5.4.6","C");
        oidDictionary.put("2.5.4.10","O");
        oidDictionary.put("2.5.4.3","CN");
        oidDictionary.put("2.5.4.5","SERIALNUMBER");
    }
}
