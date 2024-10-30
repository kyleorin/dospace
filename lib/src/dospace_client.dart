import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:meta/meta.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:xml/xml.dart' as xml;
import 'dospace_exception.dart';  // Add this import

class Client {
  final String? region;
  final String? accessKey;
  final String? secretKey;
  final String service;
  final String endpointUrl;

  @protected
  final http.Client httpClient;

  Client(
      {required this.region,
      required this.accessKey,
      required this.secretKey,
      required this.service,
      String? endpointUrl,
      http.Client? httpClient})
      : this.endpointUrl = endpointUrl ?? "https://${region}.digitaloceanspaces.com",
        this.httpClient = httpClient ?? _createSecureClient() {
    assert(this.region != null);
    assert(this.accessKey != null);
    assert(this.secretKey != null);
  }

  static http.Client _createSecureClient() {
    final httpClient = HttpClient()
      ..connectionTimeout = const Duration(seconds: 30)
      ..badCertificateCallback = (cert, host, port) => false;
    return http.Client();
  }

  Future<void> close() async {
    httpClient.close();
  }

  @protected
  Future<xml.XmlDocument> getUri(Uri uri) async {
    try {
      http.Request request = new http.Request('GET', uri);
      request.headers['User-Agent'] = 'Dart/DO Spaces Client';
      signRequest(request);
      http.StreamedResponse response = await httpClient.send(request);
      String body = await utf8.decodeStream(response.stream);
      if (response.statusCode != 200) {
        throw DOSpaceException(
            response.statusCode, response.reasonPhrase, response.headers, body);
      }
      xml.XmlDocument doc = xml.XmlDocument.parse(body);
      return doc;
    } on SocketException catch (e) {
      throw DOSpaceException(
        0,
        'Connection failed',
        {},
        'Failed to connect to DigitalOcean Spaces: ${e.message}',
      );
    } on TlsException catch (e) {
      throw DOSpaceException(
        0,
        'SSL/TLS Error',
        {},
        'SSL/TLS handshake failed: ${e.message}',
      );
    } catch (e) {
      throw DOSpaceException(
        0,
        'Unknown Error',
        {},
        'An unexpected error occurred: ${e.toString()}',
      );
    }
  }


  String _uriEncode(String str) {
    return Uri.encodeQueryComponent(str).replaceAll('+', '%20');
  }

  String _trimAll(String str) {
    String res = str.trim();
    int len;
    do {
      len = res.length;
      res = res.replaceAll('  ', ' ');
    } while (res.length != len);
    return res;
  }

  @protected
  String? signRequest(http.BaseRequest request,
      {Digest? contentSha256, bool preSignedUrl = false, int expires = 86400}) {
    String httpMethod = request.method;
    String canonicalURI = request.url.path;
    String host = request.url.host;

    DateTime date = new DateTime.now().toUtc();
    String dateIso8601 = date.toIso8601String();
    dateIso8601 = dateIso8601
            .substring(0, dateIso8601.indexOf('.'))
            .replaceAll(':', '')
            .replaceAll('-', '') +
        'Z';
    String dateYYYYMMDD = date.year.toString().padLeft(4, '0') +
        date.month.toString().padLeft(2, '0') +
        date.day.toString().padLeft(2, '0');

    String hashedPayloadStr =
        contentSha256 == null ? 'UNSIGNED-PAYLOAD' : '$contentSha256';

    String credential =
        '${accessKey}/${dateYYYYMMDD}/${region}/${service}/aws4_request';

    Map<String, String?> headers = new Map<String, String?>();
    if (!preSignedUrl) {
      request.headers['x-amz-date'] = dateIso8601;
      if (contentSha256 != null) {
        request.headers['x-amz-content-sha256'] = hashedPayloadStr;
      }
      request.headers.keys.forEach((String name) =>
          (headers[name.toLowerCase()] = request.headers[name]));
    }
    headers['host'] = host;
    List<String> headerNames = headers.keys.toList()..sort();
    String canonicalHeaders =
        headerNames.map((s) => '${s}:${_trimAll(headers[s]!)}' + '\n').join();

    String signedHeaders = headerNames.join(';');

    Map<String, String> queryParameters = new Map<String, String>()
      ..addAll(request.url.queryParameters);
    if (preSignedUrl) {
      queryParameters['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
      queryParameters['X-Amz-Credential'] = credential;
      queryParameters['X-Amz-Date'] = dateIso8601;
      queryParameters['X-Amz-Expires'] = expires.toString();
      if (contentSha256 != null) {
        queryParameters['X-Amz-Content-Sha256'] = hashedPayloadStr;
      }
      queryParameters['X-Amz-SignedHeaders'] = signedHeaders;
    }
    List<String> queryKeys = queryParameters.keys.toList()..sort();
    String canonicalQueryString = queryKeys
        .map((s) => '${_uriEncode(s)}=${_uriEncode(queryParameters[s]!)}')
        .join('&');

    if (preSignedUrl) {
      hashedPayloadStr = 'UNSIGNED-PAYLOAD';
    }

    String canonicalRequest =
        '${httpMethod}\n${canonicalURI}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n$hashedPayloadStr';

    Digest canonicalRequestHash = sha256.convert(utf8.encode(canonicalRequest));

    String stringToSign =
        'AWS4-HMAC-SHA256\n${dateIso8601}\n${dateYYYYMMDD}/${region}/${service}/aws4_request\n$canonicalRequestHash';

    Digest dateKey = new Hmac(sha256, utf8.encode("AWS4${secretKey}"))
        .convert(utf8.encode(dateYYYYMMDD));
    Digest dateRegionKey =
        new Hmac(sha256, dateKey.bytes).convert(utf8.encode(region!));
    Digest dateRegionServiceKey =
        new Hmac(sha256, dateRegionKey.bytes).convert(utf8.encode(service));
    Digest signingKey = new Hmac(sha256, dateRegionServiceKey.bytes)
        .convert(utf8.encode("aws4_request"));

    Digest signature =
        new Hmac(sha256, signingKey.bytes).convert(utf8.encode(stringToSign));

    request.headers['Authorization'] =
        'AWS4-HMAC-SHA256 Credential=${credential}, SignedHeaders=${signedHeaders}, Signature=$signature';

    if (preSignedUrl) {
      queryParameters['X-Amz-Signature'] = '$signature';
      return request.url.replace(queryParameters: queryParameters).toString();
    } else {
      return null;
    }
  }
}