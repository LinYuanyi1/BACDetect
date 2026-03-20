from __future__ import annotations


# Central rule registry for auth detection. These sets are heuristics, not a
# full semantic model, so they intentionally bias toward common Java patterns.
DEFAULT_AUTH_MIN_SCORE = 6

# Used to decide whether a guarded method is likely to be a web entrypoint.
WEB_ENDPOINT_ANNOTATIONS = {
    "Controller",
    "RestController",
    "RequestMapping",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
}

AUTH_GUARD_ANNOTATIONS = {
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "PermitAll",
    "DenyAll",
    "RequiresPermissions",
    "RequiresRoles",
    "RequiresAuthentication",
    "RequiresUser",
    "RequiresGuest",
    "SaCheckPermission",
    "SaCheckRole",
    "SaCheckLogin",
}

# Security framework base classes and interfaces that usually participate in
# authentication, authorization, or identity resolution.
FRAMEWORK_SECURITY_TYPES = {
    "AuthorizationManager",
    "AuthorizingRealm",
    "BasicAuthenticationFilter",
    "GenericFilterBean",
    "HandlerInterceptor",
    "HandlerMethodArgumentResolver",
    "OncePerRequestFilter",
    "PermissionEvaluator",
    "Realm",
    "SecurityManager",
    "ShiroFilterFactoryBean",
    "UsernamePasswordAuthenticationFilter",
}

# Security configuration methods often expose one of these framework objects.
SECURITY_CONFIG_RETURN_TYPES = {
    "AuthorizationAttributeSourceAdvisor",
    "AuthorizationManager",
    "DefaultWebSecurityManager",
    "Realm",
    "SecurityFilterChain",
    "SecurityManager",
    "SessionManager",
    "ShiroFilterFactoryBean",
}

# Framework hook methods are strong hints even when there is no annotation.
FRAMEWORK_SECURITY_METHODS = {
    "configure",
    "doFilter",
    "doFilterInternal",
    "doGetAuthenticationInfo",
    "doGetAuthorizationInfo",
    "isAccessAllowed",
    "onAccessDenied",
    "preHandle",
    "resolveArgument",
    "resolveName",
    "supportsParameter",
}

# Name-based hints are weak evidence and are only meaningful when combined with
# stronger structural or body-level signals.
AUTH_METHOD_NAME_KEYWORDS = {
    "access",
    "auth",
    "authoriz",
    "credential",
    "jwt",
    "login",
    "permission",
    "principal",
    "role",
    "token",
    "validate",
    "verify",
}

AUTH_CLASS_NAME_KEYWORDS = {
    "auth",
    "filter",
    "interceptor",
    "jwt",
    "permission",
    "realm",
    "role",
    "security",
    "token",
}

# Direct permission checks and denial handlers commonly surface as these calls.
AUTH_CALL_KEYWORDS = {
    "authorize",
    "authorization",
    "authenticate",
    "authentication",
    "checkaccess",
    "checkpermission",
    "checkrole",
    "getauthentication",
    "getprincipal",
    "hasanyauthority",
    "hasanyrole",
    "hasauthority",
    "haspermission",
    "hasrole",
    "ispermitted",
    "parsetoken",
    "unlogin",
    "unauthorized",
    "forbidden",
    "verifytoken",
    "validatetoken",
}

# Token-specific operations are separated so they can be labeled as
# token-handling logic instead of generic permission checks.
TOKEN_CALL_KEYWORDS = {
    "createtoken",
    "decodetoken",
    "generatetoken",
    "parsetoken",
    "refreshtoken",
    "verifytoken",
    "validatetoken",
}

AUTH_TYPE_HINTS = {
    "AccessDeniedException",
    "Authentication",
    "AuthorizationAttributeSourceAdvisor",
    "AuthorizationManager",
    "Claim",
    "Claims",
    "DecodedJWT",
    "JWT",
    "JWTVerifier",
    "JwtHelper",
    "PermissionEvaluator",
    "Principal",
    "Realm",
    "SecurityContextHolder",
    "SecurityManager",
    "ShiroFilterFactoryBean",
    "Subject",
}

AUTH_EXCEPTION_TYPES = {
    "AccessDeniedException",
    "AuthenticationException",
    "AuthorizationException",
    "ForbiddenException",
    "UnauthenticatedException",
    "UnauthorizedException",
}

# String literals are noisy, so only a small set of high-signal values are used.
AUTH_LITERAL_KEYWORDS = {
    "401",
    "403",
    "anon",
    "authorization",
    "authc",
    "bearer",
    "forbidden",
    "jwt",
    "permission",
    "role",
    "scope",
    "token",
    "unauthorized",
    "x-auth-token",
    "x-litemall-token",
    "x-token",
}

# A small import prior helps lift files that already pull in mainstream security
# frameworks without making imports alone enough to produce a finding.
SECURITY_IMPORT_KEYWORDS = (
    "auth0.jwt",
    "apache.shiro",
    "springframework.security",
)

AOP_IMPORT_KEYWORDS = (
    "aspectj",
    "spring.aop",
)

AOP_CLASS_ANNOTATIONS = {
    "Aspect",
}

AOP_ADVICE_ANNOTATIONS = {
    "After",
    "AfterReturning",
    "AfterThrowing",
    "Around",
    "Before",
    "Pointcut",
}

AOP_JOINPOINT_TYPES = {
    "JoinPoint",
    "ProceedingJoinPoint",
}

AOP_POINTCUT_REFERENCE_BLACKLIST = {
    "args",
    "bean",
    "call",
    "execution",
    "target",
    "this",
    "within",
}

AOP_SECURITY_KEYWORDS = {
    "access",
    "admin",
    "auth",
    "authorize",
    "jwt",
    "login",
    "permission",
    "role",
    "security",
    "token",
}

INLINE_AUTH_IDENTIFIER_KEYWORDS = {
    "auth",
    "bearer",
    "currentuser",
    "jwt",
    "login",
    "loginuser",
    "owner",
    "permission",
    "principal",
    "role",
    "roleid",
    "subject",
    "tenant",
    "token",
    "user",
    "userid",
}

INLINE_AUTH_CALL_KEYWORDS = {
    "getheader",
    "getprincipal",
    "getsubject",
    "hasrole",
    "hasauthority",
    "haspermission",
    "checkpermission",
    "checksuperpermission",
    "verifytoken",
    "validatetoken",
    "parsetoken",
}

INLINE_DENY_ACTION_KEYWORDS = {
    "accessdenied",
    "badargument",
    "forbidden",
    "senderror",
    "unauthorized",
    "unlogin",
}

INLINE_DENY_RETURN_TEXT_KEYWORDS = {
    "403",
    "false",
    "forbidden",
    "null",
    "unauthorized",
    "unlogin",
}
