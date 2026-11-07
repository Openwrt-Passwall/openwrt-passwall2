# Security & Boundary Checklist

## Pre-PR Verification Points
1. **Secrets & Credentials**: Ensure no API keys, private keys, or `.env` files are tracked in git.
2. **Input Sanitization**: Validate all inputs at network and file boundaries against strict schemas.
3. **No Dynamic Code Execution**: Ensure `eval()`, `exec()`, or unsanitized shell pipelines are absent.
4. **Error Masking**: Ensure errors return structured error envelopes without leaking sensitive stack traces.
