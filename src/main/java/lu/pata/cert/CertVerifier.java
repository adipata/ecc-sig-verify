package lu.pata.cert;

import lu.pata.cert.crt.Certificate;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class CertVerifier {
    public boolean verify(byte[] cert,byte[] trust){
        try {
            Certificate c=new Certificate(cert);
            Certificate t=new Certificate(trust);
            return c.verifyWith(t);
        } catch (IOException | CertException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | InvalidParameterSpecException | InvalidKeySpecException e) {
            e.printStackTrace();
            return false;
        }
    }
}
