databases:
  storage:
    azure:
      connectionString: DefaultEndpointsProtocol=https;AccountName=placeholder;AccountKey=placeholder==;EndpointSuffix=core.windows.net
  redshift:
    host: "placeholder"
    userName: "placeholder"
    password: "placeholder"
  identityMysql:
    host: "${mysql_endpoint}"
    replicaHost: ""
    password: "${mysql_password}"
    username: "${mysql_username}"
    useSsl: "true"
  generalMysql:
    host: "${mysql_endpoint}"
    password: "${mysql_password}"
    username: "${mysql_username}"
    useSsl: "true"
  kafka:
    brokerList: "${kafka_broker_list}"
    saslPassword: "${kafka_password}"
    saslUserName: "${kafka_username}"
    all brokers: "${kafka_all_brokers}"
  mongo:
    connectionString: "${mongo_connection_string}"
  mongo6:
    connectionString: "${mongo_connection_string}"
  redis:
    host: "${redis_endpoint}"
    username: "${redis_username}"
    password: "${redis_password}"
    port: "${redis_port}"
    tls: "false"
frontegg:
  customDomains:
    secretHeader: ${customDomains}
  analytics:
    firehoseRegion: "placeholder"
    firehoseAccessKeyId: "placeholder"
    firehoseSecretAccessKey: "placeholder"
    segmentWriteKey: "placeholder"
  xxx:
    authPublicKey: ${AUTH_PUBLIC_KEY_AUTOGENERTAED}
    fronteggClientId: ${fronteggClientId}
    fronteggApiKey: ${fronteggApiKey}
    ipStackApiKey: "placeholder"
    ipDataApiKey: "placeholder"
  apiKeys:
%{ for key, value in api_keys ~}
    ${key}: ${jsonencode(value)}
%{ endfor ~}
  applications:
    appIntegrations:
      cryptoKey: "placeholder"
    logsStreaming:
      cryptoKey: "placeholder"
    authentication:
      authenticationPrivateKey: ${AUTH_PRIVATE_KEY_AUTOGENERTAED}
    apiGateway:
      apiGatewayEncryptionSecret: "placeholder"
    directory:
      directoryServiceEncryptionKey: "placeholder"
    identity:
      publicKey: ${AUTH_PUBLIC_KEY_AUTOGENERTAED}
      cryptoKey: ${cryptoKeyV2}
      cryptoKeyV2: ${cryptoKeyV2}
      slack:
        clientId: "placeholder"
        clientSecret: "placeholder"
      google:
        clientId: "placeholder"
        clientSecret: "placeholder"
      apple:
        AppleClientId: "placeholder"
        ApplePrivateKey: |-
            "placeholder"
        AppleTeamId: "placeholder"
        AppleKeyId: "placeholder"
      github:
        clientId: "placeholder"
        clientSecret: "placeholder"
      microsoft:
        clientId: "placeholder"
        clientSecret: "placeholder"
      facebook:
        clientId: "placeholder"
        clientSecret: "placeholder"
        SessionSecret: "placeholder"
    log:
      logsServiceEncryptionKey: ${logsServiceEncryptionKey}
    teamManagement:
      secretPhrase: ${teamManagement}
    vendors:
      apiKeySecret: ${vendors_apiKeySecret}
      webhookSecret: ${vendors_webhookSecret}
      prehookSecret: ${vendors_prehookSecret}
      customDomains:
        clusterContext: "placeholder"
        cloudflareZone: "placeholder"
        cloudflareToken: "placeholder"
      segmentGoogleWriteKey: "placeholder"
    oauth:
      oauthServiceSigningKey: ${oauthServiceSigningKey}
      oauthServiceCryptoKey: ${oauthServiceCryptoKey}
    customCode:
      lambda: "placeholder"
externalServices:
  cloudflare:
    purgeCache:
      token: "placeholder"
      zone: "placeholder"
      enabled: "false"
    backegg:
      accessToken: "placeholder"
  sentry:
    dsn: "placeholder"
  sendgrid:
    ApiKey: "placeholder"
  twilio:
    token: "placeholder"
    accountId: "ACplaceholder"
  split:
    webhooks:
      secret: "placeholder"
    clientId: "placeholder"
    sdkKey: "localhost"