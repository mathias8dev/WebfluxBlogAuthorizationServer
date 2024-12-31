CREATE TABLE IF NOT EXISTS "authorization"
(
    id                         varchar(255) NOT NULL,
    registeredClientId         varchar(255) NOT NULL,
    principalName              varchar(255) NOT NULL,
    authorizationGrantType     varchar(255) NOT NULL,
    authorizedScopes           TEXT,
    attributes                 TEXT,
    state                      varchar(500),
    authorizationCodeValue     TEXT,
    authorizationCodeIssuedAt  TIMESTAMP,
    authorizationCodeExpiresAt TIMESTAMP,
    authorizationCodeMetadata  TEXT,
    accessTokenValue           TEXT,
    accessTokenIssuedAt        TIMESTAMP,
    accessTokenExpiresAt       TIMESTAMP,
    accessTokenMetadata        TEXT,
    accessTokenType            varchar(255),
    accessTokenScopes          TEXT,
    refreshTokenValue          TEXT,
    refreshTokenIssuedAt       TIMESTAMP,
    refreshTokenExpiresAt      TIMESTAMP,
    refreshTokenMetadata       TEXT,
    oidcIdTokenValue           TEXT,
    oidcIdTokenIssuedAt        TIMESTAMP,
    oidcIdTokenExpiresAt       TIMESTAMP,
    oidcIdTokenMetadata        TEXT,
    oidcIdTokenClaims          TEXT,
    userCodeValue              TEXT,
    userCodeIssuedAt           TIMESTAMP,
    userCodeExpiresAt          TIMESTAMP,
    userCodeMetadata           TEXT,
    deviceCodeValue            TEXT,
    deviceCodeIssuedAt         TIMESTAMP,
    deviceCodeExpiresAt        TIMESTAMP,
    deviceCodeMetadata         TEXT,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS client
(
    id                          varchar(255) NOT NULL,
    clientId                    varchar(255) NOT NULL,
    clientIdIssuedAt            TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    clientSecret                varchar(255),
    clientSecretExpiresAt       TIMESTAMP,
    clientName                  varchar(255) NOT NULL,
    clientAuthenticationMethods varchar(1000) NOT NULL,
    authorizationGrantTypes     varchar(1000) NOT NULL,
    redirectUris                varchar(1000),
    postLogoutRedirectUris      varchar(1000),
    scopes                      varchar(1000) NOT NULL,
    clientSettings              varchar(2000) NOT NULL,
    tokenSettings               varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS authorization_consent
(
    registeredClientId varchar(255) NOT NULL,
    principalName      varchar(255) NOT NULL,
    authorities        varchar(1000) NOT NULL,
    PRIMARY KEY (registeredClientId, principalName)
);
