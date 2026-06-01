# Remediation Notes

## Defensive Goals
- Preserve consistent HTTP framing between frontend and backend.
- Reject or sanitize illegal header bytes.
- Avoid globally disabling validation in codecs or header objects.

## Suggested Fix Areas
- `BaseZuulChannelInitializer`
- `DefaultOriginChannelInitializer`
- `ClientResponseWriter`
- `ProxyEndpoint`

## Example Defensive Pattern
```java
if (!transferEncodingHeaders.isEmpty() && !isChunkedFinalCoding(transferEncodingHeaders)) {
    rejectAndClose(ctx, req, msg, "transfer-encoding without chunked as final coding");
    return;
}
if (!transferEncodingHeaders.isEmpty()) {
    req.headers().set(HttpHeaderNames.TRANSFER_ENCODING, "chunked");
}
```

## Review Checklist
- Confirm header validation is enabled wherever user-controlled values become headers.
- Confirm proxy and origin agree on the same framing rules.
- Add regression tests for CRLF rejection and header normalization.
