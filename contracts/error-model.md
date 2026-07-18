# Error Model

```text
AgentNebulaSdkError
├── ConfigurationError
├── ProtocolError
│   ├── InvalidRequestError
│   ├── InvalidMetadataError
│   └── UnsupportedProtocolError
├── RegistrationError
├── ClientAuthenticationError
├── KeyResolutionError
├── UnsupportedAlgorithmError
├── AccessTokenError
├── DpopValidationError
├── ReplayDetectedError
├── ResourceResolutionError
└── ExternalServiceError
```

Each error contains a stable machine code, safe public message, optional internal context, and protocol mapping. Secrets and raw tokens are never included.
