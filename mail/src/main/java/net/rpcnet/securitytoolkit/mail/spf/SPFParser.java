package net.rpcnet.securitytoolkit.mail.spf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public final class SPFParser {

    public static final String SPACE = " ";
    public static final String EMPTY = "";
    public static final String V = "v=";
    public static final String SPF = "spf";
    public static final String ALL = "all";
    public static final String MX = "mx";
    public static final String A = "a";
    public static final String INCLUDE = "include:";
    public static final String IP_4 = "ip4:";
    public static final String IP_6 = "ip6:";
    public static final char CH = ':';

    private SPFParser(){
        //Private utility class constructor
    }

    public static Optional<SPFResult> parseSPF(String dnsResponse) {
        List<String> spfParameters = Arrays.stream(dnsResponse.split(SPACE)).collect(Collectors.toList());

        Optional<Integer> version = parseVersion(spfParameters);
        Optional<SPFQualifier> allQualifier = parseAllQualifier(spfParameters);
        Optional<SPFQualifier> mailExchangeQualifier = parseMailExchangeQualifier(spfParameters);
        Optional<SPFQualifier> aQualifier = parseAQualifier(spfParameters);
        List<SPFElement> includeElements = parseIncludeElements(spfParameters);
        List<SPFElement> ip4Record = parseIp4RecordElements(spfParameters);
        List<SPFElement> ip6Record = parseIp6RecordElements(spfParameters);

        return Optional.of(ImmutableSPFResult.builder()
                .version(version)
                .aQualifier(aQualifier)
                .ip4Records(ip4Record)
                .ip6Records(ip6Record)
                .includeRecords(includeElements)
                .mailExchangeQualifier(mailExchangeQualifier)
                .allQualifier(allQualifier)
                .build()
        );
    }

    private static Optional<Integer> parseVersion(List<String> spfParameters) {
        return spfParameters.stream()
                .filter(parameter -> parameter.startsWith(V))
                .map(parameter -> Integer.parseInt(parameter.replace(V+SPF, EMPTY)))
                .findFirst();
    }

    private static Optional<SPFQualifier> parseAllQualifier(List<String> spfParameters) {
        return spfParameters.stream()
                .filter(parameter -> parameter.endsWith(ALL))
                .map(SPFParser::parseQualifier)
                .findFirst();
    }

    private static Optional<SPFQualifier> parseMailExchangeQualifier(List<String> spfParameters) {
        return spfParameters.stream()
                .filter(parameter -> parameter.endsWith(MX))
                .map(SPFParser::parseQualifier)
                .findFirst();
    }

    private static List<SPFElement> parseIncludeElements(List<String> spfParameters) {
        return spfParameters.stream()
                .filter(parameter -> parameter.contains(INCLUDE))
                .map(parameter -> ImmutableSPFElement.builder().qualifier(parseQualifier(parameter)).value(parameter.substring(parameter.indexOf(CH) + 1)).build())
                .collect(Collectors.toList());
    }

    private static Optional<SPFQualifier> parseAQualifier(List<String> spfParameters) {
        return spfParameters.stream()
                .filter(parameter -> parameter.endsWith(A))
                .filter(parameter -> parameter.length() == 1 || parameter.length() == 2)
                .map(SPFParser::parseQualifier)
                .findFirst();
    }

    private static List<SPFElement> parseIp4RecordElements(List<String> spfParameters) {
        return parseGenericIpRecordElements(spfParameters, IP_4);
    }

    private static List<SPFElement> parseIp6RecordElements(List<String> spfParameters) {
        return parseGenericIpRecordElements(spfParameters, IP_6);
    }

    private static List<SPFElement> parseGenericIpRecordElements(List<String> spfParameters, String filter) {
        return spfParameters.stream()
                .filter(parameter -> parameter.contains(filter))
                .map(parameter -> ImmutableSPFElement.builder().qualifier(parseQualifier(parameter)).value(parameter.substring(parameter.indexOf(CH) + 1)).build())
                .collect(Collectors.toList());
    }

    private static SPFQualifier parseQualifier(String dnsElement){
        char qualifier = dnsElement.charAt(0);

        switch (qualifier){
            case '-':
                return SPFQualifier.FAIL;
            case '?':
                return SPFQualifier.NEUTRAL;
            case '~':
                return SPFQualifier.SOFT_FAIL;
            case '+':
            default:
                return SPFQualifier.PASS;
        }
    }
}
