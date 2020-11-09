package net.rpcnet.securitytoolkit.mail.spf;

public enum SPFQualifier {

    FAIL('-'),
    SOFT_FAIL('~'),
    NEUTRAL('?'),
    PASS('+');

    private final char sign;

    SPFQualifier(char sign){
        this.sign = sign;
    }

    public char getSign() {
        return sign;
    }
}
