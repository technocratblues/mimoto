package io.mosip.mimoto.service.impl;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import io.mosip.mimoto.service.MdocSelectiveDisclosureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.*;

@Slf4j
@Service
public class MdocSelectiveDisclosureServiceImpl implements MdocSelectiveDisclosureService {

    private static final String DOCUMENTS = "documents";
    private static final String ISSUER_SIGNED = "issuerSigned";
    private static final String NAME_SPACES = "nameSpaces";
    private static final String ELEMENT_IDENTIFIER = "elementIdentifier";

    @Override
    public String filterMdoc(String mdocBase64Url, Collection<String> selectedClaims) {
        if (mdocBase64Url == null || mdocBase64Url.isBlank()) {
            return mdocBase64Url;
        }
        if (selectedClaims == null) {
            return mdocBase64Url;
        }

        String trimmed = mdocBase64Url.trim();
        byte[] cborBytes;
        boolean isStandardBase64 = trimmed.contains("+") || trimmed.contains("/") || trimmed.endsWith("=");
        try {
            cborBytes = isStandardBase64
                    ? Base64.getDecoder().decode(trimmed)
                    : Base64.getUrlDecoder().decode(trimmed);
        } catch (IllegalArgumentException e) {
            try {
                cborBytes = Base64.getUrlDecoder().decode(trimmed);
            } catch (Exception ex) {
                log.warn("Failed to base64-decode mdoc string, returning original: {}", ex.getMessage());
                return mdocBase64Url;
            }
        }

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(cborBytes);
            List<DataItem> dataItems = new CborDecoder(bais).decode();
            if (dataItems == null || dataItems.isEmpty()) {
                return mdocBase64Url;
            }

            DataItem root = dataItems.get(0);
            Set<String> normalizedClaims = normalizeSelectedClaims(selectedClaims);
            DataItem filteredRoot = filterRoot(root, normalizedClaims);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new CborEncoder(baos).encode(filteredRoot);
            byte[] filteredBytes = baos.toByteArray();

            if (isStandardBase64) {
                return Base64.getEncoder().encodeToString(filteredBytes);
            }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(filteredBytes);
        } catch (Exception e) {
            log.error("Failed to filter mdoc CBOR, returning original: {}", e.getMessage(), e);
            return mdocBase64Url;
        }
    }

    private DataItem filterRoot(DataItem root, Set<String> normalizedClaims) {
        if (!(root instanceof Map rootMap)) {
            return root;
        }

        // Case 1: DeviceResponse (contains "documents" array)
        DataItem docsItem = getMapValue(rootMap, DOCUMENTS);
        if (docsItem instanceof Array docsArray) {
            Array filteredDocsArray = new Array();
            for (DataItem docItem : docsArray.getDataItems()) {
                if (docItem instanceof Map docMap) {
                    filteredDocsArray.add(filterDocumentMap(docMap, normalizedClaims));
                } else {
                    filteredDocsArray.add(docItem);
                }
            }
            setMapValue(rootMap, DOCUMENTS, filteredDocsArray);
            return rootMap;
        }

        // Case 2: Document (contains "issuerSigned" map)
        DataItem issuerSignedItem = getMapValue(rootMap, ISSUER_SIGNED);
        if (issuerSignedItem instanceof Map issuerSignedMap) {
            setMapValue(rootMap, ISSUER_SIGNED, filterIssuerSigned(issuerSignedMap, normalizedClaims));
            return rootMap;
        }

        // Case 3: IssuerSigned directly (contains "nameSpaces" map)
        DataItem nameSpacesItem = getMapValue(rootMap, NAME_SPACES);
        if (nameSpacesItem instanceof Map nameSpacesMap) {
            setMapValue(rootMap, NAME_SPACES, filterNameSpaces(nameSpacesMap, normalizedClaims));
            return rootMap;
        }

        return rootMap;
    }

    private Map filterDocumentMap(Map docMap, Set<String> normalizedClaims) {
        DataItem issuerSignedItem = getMapValue(docMap, ISSUER_SIGNED);
        if (issuerSignedItem instanceof Map issuerSignedMap) {
            setMapValue(docMap, ISSUER_SIGNED, filterIssuerSigned(issuerSignedMap, normalizedClaims));
        }
        return docMap;
    }

    private Map filterIssuerSigned(Map issuerSignedMap, Set<String> normalizedClaims) {
        DataItem nameSpacesItem = getMapValue(issuerSignedMap, NAME_SPACES);
        if (nameSpacesItem instanceof Map nameSpacesMap) {
            setMapValue(issuerSignedMap, NAME_SPACES, filterNameSpaces(nameSpacesMap, normalizedClaims));
        }
        return issuerSignedMap;
    }

    private Map filterNameSpaces(Map nameSpacesMap, Set<String> normalizedClaims) {
        Map filteredNameSpacesMap = new Map();
        for (DataItem nsKeyItem : nameSpacesMap.getKeys()) {
            String namespace = (nsKeyItem instanceof UnicodeString us) ? us.getString() : nsKeyItem.toString();
            DataItem nsValItem = nameSpacesMap.get(nsKeyItem);
            if (!(nsValItem instanceof Array itemsArray)) {
                continue;
            }

            Array filteredItemsArray = new Array();
            for (DataItem item : itemsArray.getDataItems()) {
                String elementId = extractElementIdentifier(item);
                if (elementId != null && isClaimSelected(namespace, elementId, normalizedClaims)) {
                    // CRITICAL: Preserve the exact original ByteString and Tag 24
                    filteredItemsArray.add(item);
                }
            }

            if (!filteredItemsArray.getDataItems().isEmpty()) {
                filteredNameSpacesMap.put(nsKeyItem, filteredItemsArray);
            }
        }
        return filteredNameSpacesMap;
    }

    private String extractElementIdentifier(DataItem item) {
        byte[] rawItemBytes = null;
        if (item instanceof ByteString bs) {
            rawItemBytes = bs.getBytes();
        }
        if (rawItemBytes == null || rawItemBytes.length == 0) {
            if (item instanceof Map map) {
                return findStringValue(map, ELEMENT_IDENTIFIER);
            }
            return null;
        }

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(rawItemBytes);
            List<DataItem> innerDecoded = new CborDecoder(bais).decode();
            if (innerDecoded != null && !innerDecoded.isEmpty() && innerDecoded.get(0) instanceof Map innerMap) {
                return findStringValue(innerMap, ELEMENT_IDENTIFIER);
            }
        } catch (CborException e) {
            log.warn("Failed to decode inner IssuerSignedItem CBOR: {}", e.getMessage());
        }
        return null;
    }

    private String findStringValue(Map map, String targetKey) {
        for (DataItem keyItem : map.getKeys()) {
            if (keyItem instanceof UnicodeString us && targetKey.equals(us.getString())) {
                DataItem valItem = map.get(keyItem);
                if (valItem instanceof UnicodeString valUs) {
                    return valUs.getString();
                }
            }
        }
        return null;
    }

    private boolean isClaimSelected(String namespace, String elementId, Set<String> normalizedClaims) {
        if (normalizedClaims == null || normalizedClaims.isEmpty()) {
            return false;
        }
        if (elementId == null) {
            return false;
        }

        String lowerElementId = elementId.toLowerCase(Locale.ROOT);
        if (normalizedClaims.contains(lowerElementId)) {
            return true;
        }

        if (namespace != null && !namespace.isBlank()) {
            String lowerNamespaced = (namespace + "." + elementId).toLowerCase(Locale.ROOT);
            if (normalizedClaims.contains(lowerNamespaced)) {
                return true;
            }
        }
        return false;
    }

    private Set<String> normalizeSelectedClaims(Collection<String> selectedClaims) {
        if (selectedClaims == null || selectedClaims.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> normalized = new HashSet<>();
        for (String claim : selectedClaims) {
            if (claim == null || claim.isBlank()) {
                continue;
            }
            String s = claim.trim();

            if (s.startsWith("$.")) {
                s = s.substring(2);
            } else if (s.startsWith("$")) {
                s = s.substring(1);
            }

            s = s.replaceFirst("^(issuerSigned\\.)?(nameSpaces\\.)?", "");
            s = s.replaceAll("\\[['\"](.*?)['\"]\\]", ".$1");
            if (s.startsWith(".")) {
                s = s.substring(1);
            }

            s = s.toLowerCase(Locale.ROOT);
            normalized.add(s);

            int lastDot = s.lastIndexOf('.');
            if (lastDot >= 0 && lastDot < s.length() - 1) {
                normalized.add(s.substring(lastDot + 1));
            }
        }
        return normalized;
    }

    private DataItem getMapValue(Map map, String key) {
        for (DataItem k : map.getKeys()) {
            if (k instanceof UnicodeString us && key.equals(us.getString())) {
                return map.get(k);
            }
        }
        return null;
    }

    private void setMapValue(Map map, String key, DataItem value) {
        DataItem targetKey = null;
        for (DataItem k : map.getKeys()) {
            if (k instanceof UnicodeString us && key.equals(us.getString())) {
                targetKey = k;
                break;
            }
        }
        if (targetKey != null) {
            map.put(targetKey, value);
        } else {
            map.put(new UnicodeString(key), value);
        }
    }
}
