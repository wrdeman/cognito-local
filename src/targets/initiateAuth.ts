import type {
  DeliveryMediumType,
  InitiateAuthRequest,
  InitiateAuthResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { v4 } from "uuid";
import {
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
  PasswordResetRequiredError,
  UnsupportedError,
  UserNotConfirmedException,
} from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import {
  encodeSessionToken,
  type SessionStore,
} from "../services/sessionStore";
import {
  attributesIncludeMatch,
  attributesToRecord,
  attributeValue,
  type MFAOption,
  type User,
} from "../services/userPoolService";
import type { Target } from "./Target";

export type InitiateAuthTarget = Target<
  InitiateAuthRequest,
  InitiateAuthResponse
>;

type InitiateAuthServices = Pick<
  Services,
  | "cognito"
  | "messages"
  | "otp"
  | "sessionStore"
  | "tokenGenerator"
  | "triggers"
>;

const verifyMfaChallenge = async (
  ctx: Context,
  user: User,
  req: InitiateAuthRequest,
  userPool: UserPoolService,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!user.MFAOptions?.length) {
    throw new NotAuthorizedError();
  }
  const smsMfaOption = user.MFAOptions?.find(
    (x): x is MFAOption & { DeliveryMedium: DeliveryMediumType } =>
      x.DeliveryMedium === "SMS",
  );
  if (!smsMfaOption) {
    throw new UnsupportedError("MFA challenge without SMS");
  }

  const deliveryDestination = attributeValue(
    smsMfaOption.AttributeName,
    user.Attributes,
  );
  if (!deliveryDestination) {
    throw new UnsupportedError(`SMS_MFA without ${smsMfaOption.AttributeName}`);
  }

  const code = services.otp();
  await services.messages.deliver(
    ctx,
    "Authentication",
    req.ClientId,
    userPool.options.Id,
    user,
    code,
    req.ClientMetadata,
    {
      DeliveryMedium: smsMfaOption.DeliveryMedium,
      AttributeName: smsMfaOption.AttributeName,
      Destination: deliveryDestination,
    },
  );

  await userPool.saveUser(ctx, {
    ...user,
    MFACode: code,
  });

  return {
    ChallengeName: "SMS_MFA",
    ChallengeParameters: {
      CODE_DELIVERY_DELIVERY_MEDIUM: "SMS",
      CODE_DELIVERY_DESTINATION: deliveryDestination,
      USER_ID_FOR_SRP: user.Username,
    },
  };
};

const verifyPasswordChallenge = async (
  ctx: Context,
  user: User,
  _req: InitiateAuthRequest,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    // The docs for the pre-token generation trigger only say that the ClientMetadata is passed as part of the
    // AdminRespondToAuthChallenge and RespondToAuthChallenge triggers.
    //
    // source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
    undefined,
    "Authentication",
  );

  await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);

  return {
    ChallengeName: "PASSWORD_VERIFIER",
    ChallengeParameters: {},
    AuthenticationResult: tokens,
  };
};

const generateCustomAuthTokens = async (
  ctx: Context,
  user: User,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
  clientMetadata: Record<string, string> | undefined,
) => {
  const userGroups = await userPool.listUserGroupMembership(ctx, user);
  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    clientMetadata,
    "Authentication",
  );

  if (tokens.RefreshToken) {
    await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);
  }

  return tokens;
};

const newPasswordChallenge = (user: User): InitiateAuthResponse => ({
  ChallengeName: "NEW_PASSWORD_REQUIRED",
  ChallengeParameters: {
    USER_ID_FOR_SRP: user.Username,
    requiredAttributes: JSON.stringify([]),
    userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
  },
  Session: v4(),
});

const userPasswordAuthFlow = async (
  ctx: Context,
  req: InitiateAuthRequest,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }

  let user = await userPool.getUserByUsername(ctx, req.AuthParameters.USERNAME);

  if (
    !user &&
    services.triggers.enabled("UserMigration", userPool.options.LambdaConfig)
  ) {
    // https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html
    //
    // Amazon Cognito invokes [the User Migration] trigger when a user does not exist in the user pool at the time
    // of sign-in with a password, or in the forgot-password flow. After the Lambda function returns successfully,
    // Amazon Cognito creates the user in the user pool.
    user = await services.triggers.userMigration(ctx, {
      clientId: req.ClientId,
      password: req.AuthParameters.PASSWORD,
      userAttributes: [],
      username: req.AuthParameters.USERNAME,
      userPoolId: userPool.options.Id,
      lambdaConfig: userPool.options.LambdaConfig,

      // UserMigration triggered by InitiateAuth passes the request ClientMetadata as ValidationData and nothing as
      // the ClientMetadata.
      //
      // Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html#cognito-user-pools-lambda-trigger-syntax-user-migration
      clientMetadata: undefined,
      validationData: req.ClientMetadata,
    });
  }

  if (!user) {
    throw new NotAuthorizedError();
  }
  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
  }
  if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
    return newPasswordChallenge(user);
  }
  if (user.Password !== req.AuthParameters.PASSWORD) {
    throw new InvalidPasswordError();
  }
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  if (
    (userPool.options.MfaConfiguration === "OPTIONAL" &&
      (user.MFAOptions ?? []).length > 0) ||
    userPool.options.MfaConfiguration === "ON"
  ) {
    return verifyMfaChallenge(ctx, user, req, userPool, services);
  }

  if (
    services.triggers.enabled(
      "PostAuthentication",
      userPool.options.LambdaConfig,
    )
  ) {
    await services.triggers.postAuthentication(ctx, {
      clientId: req.ClientId,
      // As per the InitiateAuth docs, ClientMetadata is not passed to PostAuthentication when called from InitiateAuth
      // Source: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html#API_InitiateAuth_RequestSyntax
      clientMetadata: undefined,
      lambdaConfig: userPool.options.LambdaConfig,
      source: "PostAuthentication_Authentication",
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    });
  }

  return verifyPasswordChallenge(
    ctx,
    user,
    req,
    userPool,
    userPoolClient,
    services,
  );
};

const customAuthFlow = async (
  ctx: Context,
  req: InitiateAuthRequest,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters?.USERNAME) {
    throw new InvalidParameterError("AuthParameters USERNAME is required");
  }

  const authParameters = { ...req.AuthParameters };
  let resolvedUsername = authParameters.USERNAME;

  // ------------------------------------------------------------------
  // 1) Try canonical username lookup FIRST (AWS behavior)
  // ------------------------------------------------------------------
  let user = null;
  const usernameAttributes = userPool.options.UsernameAttributes ?? [];
  const isEmailUsernamePool = usernameAttributes.includes("email");

  // ------------------------------------------------------------------
  // AWS behavior:
  // - If email is a username attribute, USERNAME is always an alias
  // - Canonical username is ALWAYS the UUID
  // ------------------------------------------------------------------
  if (!isEmailUsernamePool) {
    // Username-based pool → direct lookup
    user = await userPool.getUserByUsername(ctx, resolvedUsername);
  }

  // ------------------------------------------------------------------
  // Alias resolution (email → UUID)
  // ------------------------------------------------------------------
  if (!user && resolvedUsername.includes("@") && isEmailUsernamePool) {
    ctx.logger.warn("InitiateAuth alias resolution check", {
      providedUsername: resolvedUsername,
      clientId: req.ClientId,
      userPoolId: userPool.options.Id,
      usernameAttributes: userPool.options.UsernameAttributes,
    });
    const users = await userPool.listUsers(ctx);
    ctx.logger.warn(
      "InitiateAuth listUsers" + users.length + userPool.options.Id,
      {},
    );
    const userByEmail = users.find((candidate) =>
      attributesIncludeMatch("email", resolvedUsername, candidate.Attributes),
    );

    if (!userByEmail) {
      throw new NotAuthorizedError();
    }

    resolvedUsername = userByEmail.Username;
    authParameters.USERNAME = resolvedUsername;
    user = await userPool.getUserByUsername(ctx, resolvedUsername);

    ctx.logger?.warn("Resolved email alias to canonical username", {
      providedUsername: req.AuthParameters.USERNAME,
      resolvedUsername,
      userPoolId: userPool.options.Id,
    });
  }

  // ------------------------------------------------------------------
  // 2) Fallback: resolve email alias ONLY if user not found
  // ------------------------------------------------------------------
  if (
    !user &&
    resolvedUsername.includes("@") &&
    userPool.options.UsernameAttributes?.includes("email")
  ) {
    ctx.logger?.warn("InitiateAuth attempting email alias resolution", {
      providedUsername: resolvedUsername,
      userPoolId: userPool.options.Id,
    });

    const users = await userPool.listUsers(ctx);
    const userByEmail = users.find((candidate) =>
      attributesIncludeMatch("email", resolvedUsername, candidate.Attributes),
    );

    if (!userByEmail) {
      throw new NotAuthorizedError();
    }

    resolvedUsername = userByEmail.Username;
    authParameters.USERNAME = resolvedUsername;

    ctx.logger?.warn("Resolved email alias to canonical username", {
      providedUsername: req.AuthParameters.USERNAME,
      resolvedUsername,
      userPoolId: userPool.options.Id,
    });

    user = await userPool.getUserByUsername(ctx, resolvedUsername);
  }

  // ------------------------------------------------------------------
  // 3) Final existence check
  // ------------------------------------------------------------------
  if (!user) {
    throw new NotAuthorizedError();
  }

  // ------------------------------------------------------------------
  // 4) Status handling (unchanged)
  // ------------------------------------------------------------------
  if (user.UserStatus === "RESET_REQUIRED") {
    throw new PasswordResetRequiredError();
  }

  if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
    return newPasswordChallenge(user);
  }

  if (user.UserStatus === "UNCONFIRMED") {
    if (process.env.COGNITO_LOCAL === "true") {
      await userPool.saveUser(ctx, {
        ...user,
        ConfirmationCode: undefined,
        UserStatus: "CONFIRMED",
      });
    } else {
      throw new UserNotConfirmedException();
    }
  }
  // const defineEnabled = services.triggers.enabled("DefineAuthChallenge");
  // const createEnabled = services.triggers.enabled("CreateAuthChallenge");
  // const verifyEnabled = services.triggers.enabled("VerifyAuthChallengeResponse");
  //
  // ctx.logger.warn(
  //   {
  //     defineEnabled,
  //     createEnabled,
  //     verifyEnabled,
  //     userPoolId: userPool.options.Id,
  //     usernameAttrs: userPool.options.UsernameAttributes,
  //     lambdaConfig: userPool.options.LambdaConfig,
  //     // if triggers has any config object, dump it:
  //     triggersServiceKeys: Object.keys((services.triggers as any) ?? {}),
  //     lambdaClient: (services as any).lambdaClient ?? undefined,
  //     lambdaEndpoint:
  //       ((services.triggers as any)?.lambdaClient?.endpoint ??
  //         (services.triggers as any)?.endpoint ??
  //         (services.triggers as any)?.options?.endpoint),
  //   },
  //   "CUSTOM_AUTH trigger enablement check",
  // );

  // if (!defineEnabled || !createEnabled || !verifyEnabled) {
  //   throw new UnsupportedError("CUSTOM_AUTH triggers not configured");
  // }
  // ------------------------------------------------------------------
  // 5) Validate CUSTOM_AUTH trigger support
  // ------------------------------------------------------------------+  /**
  /* LOCAL MODE BEHAVIOR
   *
   * AWS Cognito allows CUSTOM_AUTH when triggers are configured,
   * even if the app client does not explicitly list CUSTOM_AUTH_FLOW_ONLY.
   *
   * cognito-local is stricter than AWS here, so in LOCAL mode we relax
   * the check to match real Cognito behavior.
   */
  const isLocal = process.env.COGNITO_LOCAL === "true";

  const defineEnabled =
    isLocal ||
    services.triggers.enabled(
      "DefineAuthChallenge",
      userPool.options.LambdaConfig,
    );
  const createEnabled =
    isLocal ||
    services.triggers.enabled(
      "CreateAuthChallenge",
      userPool.options.LambdaConfig,
    );
  const verifyEnabled =
    isLocal ||
    services.triggers.enabled(
      "VerifyAuthChallengeResponse",
      userPool.options.LambdaConfig,
    );

  ctx.logger.debug("CUSTOM_AUTH trigger enablement check", {
    isLocal,
    defineEnabled,
    createEnabled,
    verifyEnabled,
    userPoolId: userPool.options.Id,
    lambdaConfigKeys: Object.keys(userPool.options.LambdaConfig ?? {}),
  });

  if (!defineEnabled || !createEnabled || !verifyEnabled) {
    throw new UnsupportedError("CUSTOM_AUTH triggers not configured");
  }

  // ------------------------------------------------------------------
  // 6) Start CUSTOM_AUTH session
  // ------------------------------------------------------------------
  const session = services.sessionStore.createSession({
    clientId: req.ClientId,
    userPoolId: userPool.options.Id,
    username: user.Username,
  });

  const defineResponse = await services.triggers.defineAuthChallenge(ctx, {
    clientId: req.ClientId,
    clientMetadata: req.ClientMetadata,
    lambdaConfig: userPool.options.LambdaConfig,
    session: session.session,
    userAttributes: user.Attributes,
    username: user.Username,
    userPoolId: userPool.options.Id,
  });

  if (defineResponse.failAuthentication) {
    services.sessionStore.deleteSession(session.id);
    throw new NotAuthorizedError();
  }

  // ------------------------------------------------------------------
  // 7) Issue tokens immediately if requested
  // ------------------------------------------------------------------
  if (defineResponse.issueTokens) {
    const tokens = await generateCustomAuthTokens(
      ctx,
      user,
      userPool,
      userPoolClient,
      services,
      req.ClientMetadata,
    );

    if (services.triggers.enabled("PostAuthentication")) {
      await services.triggers.postAuthentication(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        lambdaConfig: userPool.options.LambdaConfig,
        source: "PostAuthentication_Authentication",
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
      });
    }

    services.sessionStore.deleteSession(session.id);

    return {
      ChallengeName: undefined,
      ChallengeParameters: {},
      AuthenticationResult: tokens,
    };
  }

  // ------------------------------------------------------------------
  // 8) Otherwise create a CUSTOM_CHALLENGE
  // ------------------------------------------------------------------
  const challengeName: "CUSTOM_CHALLENGE" = (defineResponse.challengeName ??
    "CUSTOM_CHALLENGE") as "CUSTOM_CHALLENGE";

  const createResponse = await services.triggers.createAuthChallenge(ctx, {
    challengeName,
    clientId: req.ClientId,
    clientMetadata: req.ClientMetadata,
    lambdaConfig: userPool.options.LambdaConfig,
    session: session.session,
    userAttributes: user.Attributes,
    username: user.Username,
    userPoolId: userPool.options.Id,
  });

  services.sessionStore.setChallenge(session.id, {
    challengeName,
    privateChallengeParameters: createResponse.privateChallengeParameters ?? {},
    publicChallengeParameters: createResponse.publicChallengeParameters ?? {},
    expectedAnswer:
      createResponse.privateChallengeParameters?.expectedAnswer ?? null,
    challengeMetadata: createResponse.challengeMetadata || undefined,
  });

  return {
    ChallengeName: "CUSTOM_CHALLENGE",
    Session: encodeSessionToken(session.id),
    ChallengeParameters: createResponse.publicChallengeParameters ?? {},
  };
};

const refreshTokenAuthFlow = async (
  ctx: Context,
  req: InitiateAuthRequest,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  services: InitiateAuthServices,
): Promise<InitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters",
    );
  }

  if (!req.AuthParameters.REFRESH_TOKEN) {
    throw new InvalidParameterError("AuthParameters REFRESH_TOKEN is required");
  }

  const user = await userPool.getUserByRefreshToken(
    ctx,
    req.AuthParameters.REFRESH_TOKEN,
  );
  if (!user) {
    throw new NotAuthorizedError();
  }

  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    // The docs for the pre-token generation trigger only say that the ClientMetadata is passed as part of the
    // AdminRespondToAuthChallenge and RespondToAuthChallenge triggers.
    //
    // source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
    undefined,
    "RefreshTokens",
  );

  return {
    ChallengeName: undefined,
    Session: undefined,
    ChallengeParameters: undefined,
    AuthenticationResult: {
      AccessToken: tokens.AccessToken,
      RefreshToken: undefined,
      IdToken: tokens.IdToken,
      NewDeviceMetadata: undefined,
      TokenType: undefined,
      ExpiresIn: undefined,
    },
  };
};

export const InitiateAuth =
  (services: InitiateAuthServices): InitiateAuthTarget =>
  async (ctx, req) => {
    const userPool = await services.cognito.getUserPoolForClientId(
      ctx,
      req.ClientId,
    );
    const userPoolClient = await services.cognito.getAppClient(
      ctx,
      req.ClientId,
    );
    if (!userPoolClient) {
      throw new NotAuthorizedError();
    }

    if (req.AuthFlow === "USER_PASSWORD_AUTH") {
      return userPasswordAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else if (req.AuthFlow === "CUSTOM_AUTH") {
      return customAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else if (
      req.AuthFlow === "REFRESH_TOKEN" ||
      req.AuthFlow === "REFRESH_TOKEN_AUTH"
    ) {
      return refreshTokenAuthFlow(ctx, req, userPool, userPoolClient, services);
    } else {
      throw new UnsupportedError(`InitAuth with AuthFlow=${req.AuthFlow}`);
    }
  };
