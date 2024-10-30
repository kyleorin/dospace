class DOSpaceException implements Exception {
  final int statusCode;
  final String? reasonPhrase;
  final Map<String, String> responseHeaders;
  final String responseBody;

  const DOSpaceException(
    this.statusCode,
    this.reasonPhrase,
    this.responseHeaders,
    this.responseBody,
  );

  @override
  String toString() {
    return "DOSpaceException { statusCode: $statusCode, reasonPhrase: \"$reasonPhrase\", responseBody: \"$responseBody\" }";
  }
}