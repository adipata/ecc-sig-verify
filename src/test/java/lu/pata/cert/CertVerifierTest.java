package lu.pata.cert;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.Security;

public class CertVerifierTest {

    @Test
    public void verify() throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] cert= IOUtils.toByteArray((new File("server.der")).toURI());
        byte[] trust=IOUtils.toByteArray((new File("server.der")).toURI());

        CertVerifier vTool=new CertVerifier();
        Assert.assertTrue(vTool.verify(cert,trust));
    }
}