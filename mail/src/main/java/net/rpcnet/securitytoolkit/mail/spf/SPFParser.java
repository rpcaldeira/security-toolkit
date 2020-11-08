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
        List<SPFElement> aRecordElements = parseARecordElements(spfParameters);
        List<SPFElement> includeElements = parseIncludeElements(spfParameters);

        return Optional.of(ImmutableSPFResult.builder()
                .version(version)
                .aRecord(aRecordElements)
                .include(includeElements)
                .mailExchange(mailExchangeQualifier)
                .all(allQualifier)
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

    private static List<SPFElement> parseARecordElements(List<String> spfParameters) {
        ArrayList<SPFElement> spfElements = new ArrayList<>();

        List<ImmutableSPFElement> ip4 = spfParameters.stream()
                .filter(parameter -> parameter.contains(IP_4))
                .map(parameter -> ImmutableSPFElement.builder().qualifier(parseQualifier(parameter)).value(parameter.substring(parameter.indexOf(CH) + 1)).build())
                .collect(Collectors.toList());
        spfElements.addAll(ip4);

        List<ImmutableSPFElement> ip6 = spfParameters.stream()
                .filter(parameter -> parameter.contains(IP_6))
                .map(parameter -> ImmutableSPFElement.builder().qualifier(parseQualifier(parameter)).value(parameter.substring(parameter.indexOf(CH) + 1)).build())
                .collect(Collectors.toList());
        spfElements.addAll(ip6);

        return spfElements;
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
