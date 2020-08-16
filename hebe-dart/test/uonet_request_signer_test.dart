import 'package:uonet_request_signer/uonet_request_signer.dart';
import 'package:test/test.dart';

void main() {
  String fullUrl;
  String fingerprint;
  String privateKey;
  String body;
  setUp(() {
    fullUrl = '/powiatwulkanowy/123456/api/mobile/register/hebe';
    fingerprint = '7EBA57E1DDBA1C249D097A9FF1C9CCDD45351A6A';
    privateKey =
        'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCbF5Tt176EpB4cX5U+PZE0XytjJ9ABDZFaBFDkaexbkuNeuLOaARjQEOlUoBmpZQXxAF8HlYqeTvPiTcnSfQIS6EdqpICuQNdwvy6CHFAe2imkbbB0aHPsGep6zH8ZxHbssazkTCnGy0j2ZtGT2/iy1GEvc/p2bOkCVcR1H1GqFp+/XpfaMwi2SRCwc67K8Fu8TjSDKNvcRT9nuenGoPA1CWoOiOCxhQA6gnB8LULPel6TVDxeBVdYor/z2GxFe/m0pa7XAKzveuUDhH8k8NlNG65MjvZhgy9iFs+eBUq7lCZ0nuIsDzjnUrLSl4ciYKj9d94qrUyF8L8D9Rl+0WlAgMBAAECggEAQ6jg3rNmyxIg0rl0ZG/LjEF26RKR7P5KQLcpouESga3HfzHvsjMCq+OWZvciFhazRd4BQkdwZxGPnfa7ieGzmhtvs1pDu8zU/hE4UClV+EG6NpVpC2Q/sn5KZRijaZoY3eMGQUFatBzCBcLZxYspfbyR3ucLbu9DE+foNB1Fh4u9RCDj3bClTsqPcNBIaLMpYr3f/bM1fFbS9LrJ7AXZQtGg/2MH58WsvV67SiYAQqGCzld/Jp74gmod4Ii0w2XWZ7OeixdF2xr1j7TK0dUUlrrOrb1cgOWSOEXyy3RX/iF7R8uuLXiRfo1URh6VNPoOtrC6fHCrCp1iRBo08qOk4QKBgQDxqLrWA7gKcTr2yQeGfETXOAYi0xqbNj5A9eVC0XngxnFuwWc5zyg3Ps3c0UK2qTSSFv4SoeEHQM+U0+9LjYzIRSUH7zy4zBrBlLtTQCysSuuZ9QfgO55b3/QEYkyx6Hz/z/gg53jKHjsUKIftGMwJ6C1M2svbBNYCsWrUuYcsbQKBgQDN9gkVDABIeWUtKDHyB5HGcVbsg7Ji7GhMjdFA0GB+9kR0doKNctrzxKn65BI2uTWg+mxaw5V+UeJOIaeFsv2uClYJYn1F55VT7NIx3CLFv6zFRSiMSKz2W+NkwGjQqR7D3DeEyalpjeQeMdpHZg27LMbdVkzy/cK8EM9ZQlRLGQKBgQCpB2wn5dIE+85Sb6pj1ugP4Y/pK9+gUQCaT2RcqEingCY3Ye/h75QhkDxOB9CyEwhCZvKv9aqAeES5xMPMBOZD7plIQ34lhB3y6SVdxbV5ja3dshYgMZNCkBMOPfOHPSaxh7X2zfEe7qZEI1Vv8bhF9bA54ZBVUbyfhZlD0cFKwQKBgQC9BnXHb0BDQ8br7twH+ZJ8wkC4yRXLXJVMzUujZJtrarHhAXNIRoVU/MXUkcV1m/3wRGV119M4IAbHFnQdbO0N8kaMTmwS4DxYzh0LzbHMM+JpGtPgDENRx3unWD/aYZzuvQnnQP3O9n7Kh46BwNQRWUMamL3+tY8n83WZwhqC4QKBgBTUzHy0sEEZ3hYgwU2ygbzC0vPladw2KqtKy+0LdHtx5pqE4/pvhVMpRRTNBDiAvb5lZmMB/B3CzoiMQOwczuus8Xsx7bEci28DzQ+g2zt0/bC2Xl+992Ass5PP5NtOrP/9QiTNgoFSCrVnZnNzQqpjCrFsjfOD2fiuFLCD6zi6';
    body = '{}';
  });

  test('Tests', () {
    final values = getSignatureValues(fingerprint, privateKey, body, fullUrl,
        DateTime.utc(2020, 3, 14, 4, 14, 15));

    expect(
        values.digest, 'SHA-256=RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=');
    expect(values.canonicalUrl, 'api%2fmobile%2fregister%2fhebe');
    expect(values.signature,
        'keyId="7EBA57E1DDBA1C249D097A9FF1C9CCDD45351A6A",headers="vCanonicalUrl Digest vDate",algorithm="sha256withrsa",signature=Base64(SHA256withRSA(jQHXSRwBv7d4tTz4rnWL2jo5N6hpPjQ6waSDgu07XK13AqmRNHb0yL4KfYZqEIJFtVyWDKq7m6k7oAhPxaEWQphG3gC2+hD94siMj2igN8xSMAKN3N/Aw17cRaagVufnGxr2iVN3uAUW+F6HAuP1uP7rWWAUfkyFmC8NYUKRq8fQ/NXV3or15u/LXLoM9lO7YqC1YEynVQzk7ERIcbXWBF9yPqQt3vZwNxO9qq0vEsq0a1SXH8x4J9kSQBWrVPwrxPEet0okdX5eE23B0m8gDDlcSCOk1fQWPLNlBRcp2EV1cMGvgNRAxb39hKxXvXTXhB3yNtod4xM0lJgEKWGo+A==))');
  });
}
