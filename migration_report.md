# AuditHound Environment Migration Report
Generated: 2025-06-16T20:34:41.369903

## Summary
- Files scanned: 496
- Patterns found: 5
- Files with issues: 3

## Hardcoded Values Found

### run_unified_dashboard.py

- **Line 159**: file_paths
  - Value: `./credentials/gcp-service-account.json...`
  - Suggested env var: `CREDENTIALS_PATH_CREDENTIALS_GCP_SERVICE_ACCOUNT_JSON`

### src/security/secrets_manager.py

- **Line 44**: passwords
  - Value: `password...`
  - Suggested env var: `PASSWORD_PASSWORD_PASSWORD`

### coral_env/lib/python3.13/site-packages/pip/_vendor/truststore/_openssl.py

- **Line 10**: file_paths
  - Value: `/etc/ssl/cert.pem...`
  - Suggested env var: `ETC_SSL_CERT_PEM`

- **Line 12**: file_paths
  - Value: `/etc/pki/tls/cert.pem...`
  - Suggested env var: `ETC_PKI_TLS_CERT_PEM`

- **Line 16**: file_paths
  - Value: `/etc/ssl/ca-bundle.pem...`
  - Suggested env var: `ETC_SSL_CA_BUNDLE_PEM`

## Recommendations

1. **Review all found values** - Some may be test/example data
2. **Set up secrets management** - Use HashiCorp Vault or AWS Secrets Manager
3. **Update CI/CD** - Configure environment variables in deployment
4. **Test thoroughly** - Ensure application works with new configuration
5. **Update documentation** - Document required environment variables

## Next Steps

1. Generate .env file: `python migrate_to_env_vars.py --generate-env`
2. Review and update environment variables
3. Test application: `python -m src.security.config_manager`
4. Apply migration: `python migrate_to_env_vars.py --execute`
