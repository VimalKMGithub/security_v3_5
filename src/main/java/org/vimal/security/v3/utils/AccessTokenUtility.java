package org.vimal.security.v3.utils;

import io.getunleash.Unleash;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.vimal.security.v3.configs.PropertiesConfig;
import org.vimal.security.v3.encryptordecryptors.GenericAesRandomEncryptorDecryptor;
import org.vimal.security.v3.encryptordecryptors.GenericAesStaticEncryptorDecryptor;
import org.vimal.security.v3.enums.MfaType;
import org.vimal.security.v3.exceptions.SimpleBadRequestException;
import org.vimal.security.v3.exceptions.UnauthorizedException;
import org.vimal.security.v3.impls.UserDetailsImpl;
import org.vimal.security.v3.models.PermissionModel;
import org.vimal.security.v3.models.RoleModel;
import org.vimal.security.v3.models.UserModel;
import org.vimal.security.v3.repos.UserRepo;
import org.vimal.security.v3.services.MailService;
import org.vimal.security.v3.services.RedisService;
import ua_parser.Client;
import ua_parser.Parser;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.vimal.security.v3.enums.AccessTokenClaims.*;
import static org.vimal.security.v3.enums.FeatureFlags.EMAIL_CONFIRMATION_ON_NEW_SIGN_IN;
import static org.vimal.security.v3.enums.MailType.NEW_SIGN_IN_CONFIRMATION;

@Component
public class AccessTokenUtility {
    private static final long ACCESS_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(30);
    private static final long ACCESS_TOKEN_EXPIRES_IN_MILLI_SECONDS = ACCESS_TOKEN_EXPIRES_IN_SECONDS * 1000;
    private static final long MILLI_SECONDS_TO_ADD_IN_NOW = TimeUnit.MINUTES.toMillis(1);
    private static final long REFRESH_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(60 * 24 * 7);
    private static final Duration ACCESS_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS);
    private static final Duration REFRESH_TOKEN_EXPIRES_IN_DURATION = Duration.ofSeconds(REFRESH_TOKEN_EXPIRES_IN_SECONDS);
    private static final AlgorithmConstraints ACCESS_TOKEN_KEY_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT,
            KeyManagementAlgorithmIdentifiers.A256KW
    );
    private static final AlgorithmConstraints ACCESS_TOKEN_ENCRYPTION_ALGORITHM_CONSTRAINTS = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.PERMIT,
            ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512
    );
    private static final Parser USER_AGENT_PARSER = new Parser();
    private static final String X_DEVICE_ID_HEADER = "X-Device-ID";
    private static final String ACCESS_TOKEN_PREFIX = "SECURITY_V3_ACCESS_TOKEN:";
    private static final String USER_DEVICE_IDS_PREFIX = "SECURITY_V3_USER_DEVICE_IDS:";
    private static final String USER_DEVICES_STATS_PREFIX = "SECURITY_V3_USER_DEVICES_STATS:";
    private static final String REFRESH_TOKEN_PREFIX = "SECURITY_V3_REFRESH_TOKEN:";
    private static final String REFRESH_TOKEN_USER_ID_MAPPING_PREFIX = "SECURITY_V3_REFRESH_TOKEN_USER_ID_MAPPING:";
    private static final String REFRESH_TOKEN_MAPPING_PREFIX = "SECURITY_V3_REFRESH_TOKEN_MAPPING:";
    private final SecretKey signingKey;
    private final SecretKey encryptionKey;
    private final UserRepo userRepo;
    private final RedisService redisService;
    private final GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor;
    private final GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor;
    private final Unleash unleash;
    private final MailService mailService;

    public AccessTokenUtility(PropertiesConfig propertiesConfig,
                              UserRepo userRepo,
                              RedisService redisService,
                              GenericAesRandomEncryptorDecryptor genericAesRandomEncryptorDecryptor,
                              GenericAesStaticEncryptorDecryptor genericAesStaticEncryptorDecryptor,
                              Unleash unleash,
                              MailService mailService) throws NoSuchAlgorithmException {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64
                .decode(propertiesConfig.getAccessTokenSigningSecretKey()));
        this.encryptionKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256")
                        .digest(propertiesConfig.getAccessTokenEncryptionSecretKey().getBytes()),
                "AES"
        );
        this.userRepo = userRepo;
        this.redisService = redisService;
        this.genericAesRandomEncryptorDecryptor = genericAesRandomEncryptorDecryptor;
        this.genericAesStaticEncryptorDecryptor = genericAesStaticEncryptorDecryptor;
        this.unleash = unleash;
        this.mailService = mailService;
    }

    private Map<String, Object> buildTokenClaims(UserModel user,
                                                 HttpServletRequest request) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(DEVICE_ID.name(), request.getHeader(X_DEVICE_ID_HEADER));
        claims.put(USER_ID.name(), user.getId().toString());
        claims.put(USERNAME.name(), user.getUsername());
        claims.put(EMAIL.name(), user.getEmail());
        claims.put(REAL_EMAIL.name(), user.getRealEmail());
        Set<String> authorities = new HashSet<>();
        for (RoleModel role : user.getRoles()) {
            authorities.add(role.getRoleName());
            for (PermissionModel permission : role.getPermissions()) {
                authorities.add(permission.getPermissionName());
            }
        }
        claims.put(AUTHORITIES.name(), authorities);
        claims.put(MFA_ENABLED.name(), user.isMfaEnabled());
        Set<String> mfaMethods = new HashSet<>();
        for (MfaType mfaType : user.getMfaMethods()) {
            mfaMethods.add(mfaType.name());
        }
        claims.put(MFA_METHODS.name(), mfaMethods);
        Instant now = Instant.now();
        claims.put(ISSUED_AT.name(), now.toString());
        claims.put(EXPIRATION.name(), now.plusSeconds(ACCESS_TOKEN_EXPIRES_IN_SECONDS).toString());
        return claims;
    }

    private String signToken(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .signWith(signingKey)
                .compact();
    }

    private String encryptToken(String jws) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jwe.setKey(encryptionKey);
        jwe.setAlgorithmConstraints(ACCESS_TOKEN_KEY_ALGORITHM_CONSTRAINTS);
        jwe.setContentEncryptionAlgorithmConstraints(ACCESS_TOKEN_ENCRYPTION_ALGORITHM_CONSTRAINTS);
        jwe.setPayload(jws);
        return jwe.getCompactSerialization();
    }

    private String generateRefreshToken(UserModel user,
                                        HttpServletRequest request) throws Exception {
        String encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(
                user,
                request
        );
        String existingEncryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
        if (existingEncryptedRefreshToken != null) {
            return genericAesRandomEncryptorDecryptor.decrypt(existingEncryptedRefreshToken);
        }
        String refreshToken = UUID.randomUUID().toString();
        String encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKey(refreshToken);
        String encryptedRefreshTokenUserIdMappingKey = getEncryptedRefreshTokenUserIdMappingKey(refreshToken);
        try {
            redisService.save(
                    encryptedRefreshTokenKey,
                    genericAesRandomEncryptorDecryptor.encrypt(refreshToken),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION
            );
            redisService.save(
                    encryptedRefreshTokenMappingKey,
                    genericAesRandomEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER)),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION
            );
            redisService.save(
                    encryptedRefreshTokenUserIdMappingKey,
                    genericAesRandomEncryptorDecryptor.encrypt(user.getId().toString()),
                    REFRESH_TOKEN_EXPIRES_IN_DURATION
            );
            return refreshToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(
                    encryptedRefreshTokenKey,
                    encryptedRefreshTokenMappingKey,
                    encryptedRefreshTokenUserIdMappingKey
            ));
            throw new RuntimeException("Failed to generate refresh token", ex);
        }
    }

    private String getEncryptedRefreshTokenKey(UserModel user,
                                               HttpServletRequest request) throws Exception {
        return getEncryptedRefreshTokenKey(
                user.getId(),
                request
        );
    }

    private String getEncryptedRefreshTokenKey(UUID userId,
                                               HttpServletRequest request) throws Exception {
        return getEncryptedRefreshTokenKey(
                userId,
                request.getHeader(X_DEVICE_ID_HEADER)
        );
    }

    private String getEncryptedRefreshTokenKey(UUID userId,
                                               String deviceId) throws Exception {
        return getEncryptedRefreshTokenKey(
                userId.toString(),
                deviceId
        );
    }

    private String getEncryptedRefreshTokenKey(String userId,
                                               String deviceId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_PREFIX + userId + ":" + deviceId);
    }

    private String getEncryptedRefreshTokenMappingKey(String refreshToken) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_MAPPING_PREFIX + refreshToken);
    }

    private String getEncryptedRefreshTokenUserIdMappingKey(String refreshToken) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(REFRESH_TOKEN_USER_ID_MAPPING_PREFIX + refreshToken);
    }

    private Map<String, Object> generateAccessToken(UserModel user,
                                                    HttpServletRequest request,
                                                    boolean deviceIdChecked) throws Exception {
        if (!deviceIdChecked) {
            checkDeviceId(request);
        }
        String encryptedDeviceIdsKey = getEncryptedDeviceIdsKey(user);
        String encryptedDeviceId = genericAesStaticEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER));
        Double score = redisService.getZSetMemberScore(
                encryptedDeviceIdsKey,
                encryptedDeviceId
        );
        long now = Instant.now().toEpochMilli();
        Map<String, Object> accessToken = new HashMap<>();
        String encryptedAccessTokenKey = getEncryptedAccessTokenKey(
                user,
                request
        );
        if (score == null || score < now + MILLI_SECONDS_TO_ADD_IN_NOW) {
            Boolean newSignIn = redisService.addZSetMember(
                    encryptedDeviceIdsKey,
                    encryptedDeviceId,
                    now + ACCESS_TOKEN_EXPIRES_IN_MILLI_SECONDS,
                    REFRESH_TOKEN_EXPIRES_IN_DURATION
            );
            sendEmailConfirmationOnNewSignIn(
                    newSignIn,
                    user
            );
            addDeviceStats(
                    user,
                    encryptedDeviceId,
                    request,
                    now
            );
            String encryptedAccessToken = encryptToken(signToken(buildTokenClaims(
                    user,
                    request
            )));
            redisService.save(
                    encryptedAccessTokenKey,
                    genericAesRandomEncryptorDecryptor.encrypt(encryptedAccessToken),
                    ACCESS_TOKEN_EXPIRES_IN_DURATION
            );
            accessToken.put("access_token", encryptedAccessToken);
            accessToken.put("expires_in_seconds", ACCESS_TOKEN_EXPIRES_IN_SECONDS);
        } else {
            accessToken.put("access_token", genericAesRandomEncryptorDecryptor.decrypt(redisService.get(encryptedAccessTokenKey)));
            accessToken.put("expires_in_seconds", redisService.getTtl(encryptedAccessTokenKey));
        }
        accessToken.put("token_type", "Bearer");
        return accessToken;
    }

    private void checkDeviceId(HttpServletRequest request) {
        if (request.getHeader(X_DEVICE_ID_HEADER) == null || request.getHeader(X_DEVICE_ID_HEADER).isBlank()) {
            throw new SimpleBadRequestException("X-Device-ID header is required");
        }
    }

    private String getEncryptedDeviceIdsKey(UserModel user) throws Exception {
        return getEncryptedDeviceIdsKey(user.getId());
    }

    private String getEncryptedDeviceIdsKey(UUID userId) throws Exception {
        return getEncryptedDeviceIdsKey(userId.toString());
    }

    private String getEncryptedDeviceIdsKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(USER_DEVICE_IDS_PREFIX + userId);
    }

    private String getEncryptedAccessTokenKey(UserModel user,
                                              HttpServletRequest request) throws Exception {
        return getEncryptedAccessTokenKey(
                user.getId(),
                request
        );
    }

    private String getEncryptedAccessTokenKey(UUID userId,
                                              HttpServletRequest request) throws Exception {
        return getEncryptedAccessTokenKey(
                userId,
                request.getHeader(X_DEVICE_ID_HEADER)
        );
    }

    private String getEncryptedAccessTokenKey(UUID userId,
                                              String deviceId) throws Exception {
        return getEncryptedAccessTokenKey(
                userId.toString(),
                deviceId
        );
    }

    private String getEncryptedAccessTokenKey(String userId,
                                              String deviceId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(ACCESS_TOKEN_PREFIX + userId + ":" + deviceId);
    }

    private void sendEmailConfirmationOnNewSignIn(Boolean newSignIn,
                                                  UserModel user) throws Exception {

        if (newSignIn != null && newSignIn && unleash.isEnabled(EMAIL_CONFIRMATION_ON_NEW_SIGN_IN.name())) {
            mailService.sendEmailAsync(
                    genericAesStaticEncryptorDecryptor.decrypt(user.getEmail()),
                    "New Sign In Detected",
                    "",
                    NEW_SIGN_IN_CONFIRMATION
            );
        }
    }

    private void addDeviceStats(UserModel user,
                                String encryptedDeviceId,
                                HttpServletRequest request,
                                long now) throws Exception {
        Client client = USER_AGENT_PARSER.parse(request.getHeader("User-Agent"));
        StringBuilder deviceInfo = new StringBuilder();
        deviceInfo.append(client.device)
                .append(";")
                .append(client.os)
                .append(";")
                .append(client.userAgent);
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isBlank()) {
            ipAddress = request.getRemoteAddr();
        }
        deviceInfo.append(";")
                .append(ipAddress);
        deviceInfo.append(";")
                .append(now);
        redisService.addHashMember(
                getEncryptedDeviceStatsKey(user),
                encryptedDeviceId,
                genericAesRandomEncryptorDecryptor.encrypt(deviceInfo.toString()),
                REFRESH_TOKEN_EXPIRES_IN_DURATION
        );
    }

    private String getEncryptedDeviceStatsKey(UserModel user) throws Exception {
        return getEncryptedDeviceStatsKey(user.getId());
    }

    private String getEncryptedDeviceStatsKey(UUID userId) throws Exception {
        return getEncryptedDeviceStatsKey(userId.toString());
    }

    private String getEncryptedDeviceStatsKey(String userId) throws Exception {
        return genericAesStaticEncryptorDecryptor.encrypt(USER_DEVICES_STATS_PREFIX + userId);
    }

    public Map<String, Object> generateTokens(UserModel user,
                                              HttpServletRequest request) throws Exception {
        Map<String, Object> tokens = generateAccessToken(
                user,
                request,
                false
        );
        tokens.put("refresh_token", generateRefreshToken(
                user,
                request
        ));
        user.recordSuccessfulLogin();
        userRepo.save(user);
        return tokens;
    }

    private String decryptToken(String token) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(encryptionKey);
        jwe.setCompactSerialization(token);
        return jwe.getPayload();
    }

    private Claims parseToken(String jws) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(jws)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    public UserDetailsImpl verifyAccessToken(String accessToken,
                                             HttpServletRequest request) throws Exception {
        checkDeviceId(request);
        Claims claims = parseToken(decryptToken(accessToken));
        if (!claims.get(
                DEVICE_ID.name(),
                String.class
        ).equals(request.getHeader(X_DEVICE_ID_HEADER))) {
            throw new UnauthorizedException("Invalid token");
        }
        if (Instant.parse(claims.get(
                                ISSUED_AT.name(),
                                String.class
                        )
                )
                .isAfter(Instant.now())) {
            throw new UnauthorizedException("Token for future");
        }
        if (Instant.parse(claims.get(
                                EXPIRATION.name(),
                                String.class
                        )
                )
                .isBefore(Instant.now())) {
            throw new UnauthorizedException("Token expired");
        }
        String userId = claims.get(
                USER_ID.name(),
                String.class
        );
        if (redisService.get(getEncryptedAccessTokenKey(
                userId,
                request.getHeader(X_DEVICE_ID_HEADER)
        )) == null) {
            throw new UnauthorizedException("Invalid token");
        }
        UserModel user = new UserModel();
        user.setId(UUID.fromString(userId));
        user.setUsername(claims.get(
                USERNAME.name(),
                String.class
        ));
        user.setEmail(claims.get(
                EMAIL.name(),
                String.class
        ));
        user.setRealEmail(claims.get(
                REAL_EMAIL.name(),
                String.class
        ));
        user.setMfaEnabled(claims.get(
                MFA_ENABLED.name(),
                Boolean.class
        ));
        Set<MfaType> mfaMethods = new HashSet<>();
        for (String mfaMethod : (List<String>) claims.get(
                MFA_METHODS.name(),
                List.class
        )) {
            mfaMethods.add(MfaType.valueOf(mfaMethod));
        }
        user.setMfaMethods(mfaMethods);
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        for (String authority : (List<String>) claims.get(
                AUTHORITIES.name(),
                List.class
        )) {
            authorities.add(new SimpleGrantedAuthority(authority));
        }
        return new UserDetailsImpl(user, authorities);
    }

    public void revokeAccessToken(UserModel user,
                                  HttpServletRequest request) throws Exception {
        redisService.updateZSetMemberScore(
                getEncryptedDeviceIdsKey(user),
                genericAesStaticEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER)),
                Instant.now().toEpochMilli() - ACCESS_TOKEN_EXPIRES_IN_MILLI_SECONDS
        );
        redisService.delete(getEncryptedAccessTokenKey(
                user,
                request
        ));
    }

    public void logout(UserModel user,
                       HttpServletRequest request) throws Exception {
        Set<String> keys = new HashSet<>();
        keys.add(getEncryptedAccessTokenKey(
                user,
                request
        ));
        String encryptedDeviceId = genericAesStaticEncryptorDecryptor.encrypt(request.getHeader(X_DEVICE_ID_HEADER));
        redisService.removeZSetMember(
                getEncryptedDeviceIdsKey(user),
                encryptedDeviceId
        );
        redisService.removeHashMember(
                getEncryptedDeviceStatsKey(user),
                encryptedDeviceId
        );
        String encryptedRefreshTokenKey = getEncryptedRefreshTokenKey(
                user,
                request
        );
        keys.add(encryptedRefreshTokenKey);
        String encryptedRefreshToken = redisService.get(encryptedRefreshTokenKey);
        if (encryptedRefreshToken != null) {
            String refreshToken = genericAesRandomEncryptorDecryptor.decrypt(encryptedRefreshToken);
            keys.add(getEncryptedRefreshTokenMappingKey(refreshToken));
            keys.add(getEncryptedRefreshTokenUserIdMappingKey(refreshToken));
        }
        redisService.deleteAll(keys);
    }

    public void logoutFromDevices(UserModel user,
                                  Set<String> deviceIds) throws Exception {
        Set<String> keys = new HashSet<>();
        String tempStr;
        for (String encryptedDeviceId : deviceIds) {
            if (encryptedDeviceId == null || encryptedDeviceId.isBlank()) {
                continue;
            }
            try {
                tempStr = genericAesStaticEncryptorDecryptor.decrypt(encryptedDeviceId);
            } catch (Exception ex) {
                continue;
            }
            keys.add(getEncryptedAccessTokenKey(
                    user.getId(),
                    tempStr
            ));
            redisService.removeZSetMember(
                    getEncryptedDeviceIdsKey(user),
                    encryptedDeviceId
            );
            redisService.removeHashMember(
                    getEncryptedDeviceStatsKey(user),
                    encryptedDeviceId
            );
            tempStr = getEncryptedRefreshTokenKey(
                    user.getId(),
                    tempStr
            );
            keys.add(tempStr);
            tempStr = redisService.get(tempStr);
            if (tempStr != null) {
                tempStr = genericAesRandomEncryptorDecryptor.decrypt(tempStr);
                keys.add(getEncryptedRefreshTokenMappingKey(tempStr));
                keys.add(getEncryptedRefreshTokenUserIdMappingKey(tempStr));
            }
        }
        if (!keys.isEmpty()) {
            redisService.deleteAll(keys);
        }
    }

    public void revokeTokens(Set<UserModel> users) throws Exception {
        Set<String> encryptedKeys = new HashSet<>();
        Set<String> encryptedRefreshTokenKeys = new HashSet<>();
        for (UserModel user : users) {
            addMembers(
                    user.getId(),
                    encryptedKeys,
                    encryptedRefreshTokenKeys
            );
        }
        proceedAndRevokeTokens(
                encryptedKeys,
                encryptedRefreshTokenKeys
        );
    }

    private void addMembers(UUID userId,
                            Set<String> encryptedKeys,
                            Set<String> encryptedRefreshTokenKeys) throws Exception {
        String tempStr = getEncryptedDeviceIdsKey(userId);
        encryptedKeys.add(tempStr);
        encryptedKeys.add(getEncryptedDeviceStatsKey(userId));
        Set<String> members = redisService.getAllZSetMembers(tempStr);
        if (members != null && !members.isEmpty()) {
            for (String encryptedDeviceId : members) {
                tempStr = genericAesStaticEncryptorDecryptor.decrypt(encryptedDeviceId);
                encryptedKeys.add(getEncryptedAccessTokenKey(
                        userId,
                        tempStr
                ));
                tempStr = getEncryptedRefreshTokenKey(
                        userId,
                        tempStr
                );
                encryptedKeys.add(tempStr);
                encryptedRefreshTokenKeys.add(tempStr);
            }
        }
    }

    private void proceedAndRevokeTokens(Set<String> encryptedKeys,
                                        Set<String> encryptedRefreshTokenKeys) throws Exception {
        String decryptedRefreshToken;
        for (String encryptedRefreshToken : redisService.getAll(encryptedRefreshTokenKeys)) {
            if (encryptedRefreshToken != null) {
                decryptedRefreshToken = genericAesRandomEncryptorDecryptor.decrypt(encryptedRefreshToken);
                encryptedKeys.add(getEncryptedRefreshTokenMappingKey(decryptedRefreshToken));
                encryptedKeys.add(getEncryptedRefreshTokenUserIdMappingKey(decryptedRefreshToken));
            }
        }
        if (!encryptedKeys.isEmpty()) {
            redisService.deleteAll(encryptedKeys);
        }
    }

    public void revokeTokensByUsersIds(Set<UUID> userIds) throws Exception {
        Set<String> encryptedKeys = new HashSet<>();
        Set<String> encryptedRefreshTokenKeys = new HashSet<>();
        for (UUID userId : userIds) {
            addMembers(
                    userId,
                    encryptedKeys,
                    encryptedRefreshTokenKeys
            );
        }
        proceedAndRevokeTokens(
                encryptedKeys,
                encryptedRefreshTokenKeys
        );
    }

    public void revokeRefreshToken(String refreshToken) throws Exception {
        String encryptedRefreshTokenMappingKey = getEncryptedRefreshTokenMappingKey(refreshToken);
        Set<String> keys = new HashSet<>();
        keys.add(encryptedRefreshTokenMappingKey);
        String encryptedRefreshTokenUserIdMappingKey = getEncryptedRefreshTokenUserIdMappingKey(refreshToken);
        keys.add(encryptedRefreshTokenUserIdMappingKey);
        String encryptedUserId = redisService.get(encryptedRefreshTokenUserIdMappingKey);
        if (encryptedUserId != null) {
            keys.add(getEncryptedRefreshTokenKey(
                    genericAesRandomEncryptorDecryptor.decrypt(encryptedUserId),
                    getDeviceId(encryptedRefreshTokenMappingKey)
            ));
        } else {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        redisService.deleteAll(keys);
    }

    private String getDeviceId(String encryptedRefreshTokenMappingKey) throws Exception {
        String encryptedDeviceId = redisService.get(encryptedRefreshTokenMappingKey);
        if (encryptedDeviceId != null) {
            return genericAesRandomEncryptorDecryptor.decrypt(encryptedDeviceId);
        }
        throw new SimpleBadRequestException("Invalid refresh token");
    }

    private UserModel verifyRefreshToken(String refreshToken,
                                         HttpServletRequest request) throws Exception {
        checkDeviceId(request);
        String deviceId = getDeviceId(getEncryptedRefreshTokenMappingKey(refreshToken));
        if (!deviceId.equals(request.getHeader(X_DEVICE_ID_HEADER))) {
            throw new SimpleBadRequestException("Invalid refresh token");
        }
        String encryptedUserId = redisService.get(getEncryptedRefreshTokenUserIdMappingKey(refreshToken));
        if (encryptedUserId != null) {
            return userRepo.findById(UUID.fromString(genericAesRandomEncryptorDecryptor.decrypt(encryptedUserId)))
                    .orElseThrow(() -> new SimpleBadRequestException("Invalid refresh token"));
        }
        throw new SimpleBadRequestException("Invalid refresh token");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken,
                                                  HttpServletRequest request) throws Exception {
        return generateAccessToken(
                verifyRefreshToken(
                        refreshToken,
                        request
                ),
                request,
                true
        );
    }
}
