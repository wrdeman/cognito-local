import type {
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import type { Services } from "../services";
import {
  decodeSessionToken,
  encodeSessionToken,
} from "../services/sessionStore";
import type { User, UserPoolService } from "../services/userPoolService";
import type { Target } from "./Target";

export type RespondToAuthChallengeTarget = Target<
  RespondToAuthChallengeRequest,
  RespondToAuthChallengeResponse
>;

type RespondToAuthChallengeService = Pick<
  Services,
  | "clock"
  | "cognito"
  | "sessionStore"
  | "triggers"
  | "tokenGenerator"
>;

const customAuthChallenge = async (
  ctx: Context,
  req: RespondToAuthChallengeRequest,
  userPool: UserPoolService,
  userPoolClient: AppClient,
  user: User,
  services: RespondToAuthChallengeService,
): Promise<RespondToAuthChallengeResponse> => {
  if (
    !services.triggers.enabled("DefineAuthChallenge") ||
    !services.triggers.enabled("CreateAuthChallenge") ||
    !services.triggers.enabled("VerifyAuthChallengeResponse")
  ) {
    throw new UnsupportedError("CUSTOM_AUTH triggers not configured");
  }

  const sessionId = decodeSessionToken(req.Session!);
  const authSession = services.sessionStore.getSession(sessionId);

  if (!authSession || authSession.username !== user.Username) {
    throw new NotAuthorizedError();
  }

  if (!authSession.challenge) {
    throw new NotAuthorizedError();
  }

  const challengeAnswer =
    req.ChallengeResponses?.ANSWER ??
    req.ChallengeResponses?.CHALLENGE_ANSWER ??
    req.ChallengeResponses?.SMS_MFA_CODE;

  if (challengeAnswer === undefined) {
    throw new InvalidParameterError("Missing required parameter ANSWER");
  }

  const verifyResponse = await services.triggers.verifyAuthChallengeResponse(
    ctx,
    {
      challengeAnswer,
      clientId: req.ClientId,
      clientMetadata: req.ClientMetadata,
      privateChallengeParameters:
        authSession.challenge.privateChallengeParameters,
      session: authSession.session,
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    },
  );

  const answerCorrect =
    verifyResponse?.answerCorrect ??
    (authSession.challenge.expectedAnswer !== null &&
      challengeAnswer === authSession.challenge.expectedAnswer);

  const sessionWithResult = services.sessionStore.recordChallengeResult(
    sessionId,
    answerCorrect,
  );

  const defineResponse = await services.triggers.defineAuthChallenge(ctx, {
    clientId: req.ClientId,
    clientMetadata: req.ClientMetadata,
    session: sessionWithResult.session,
    userAttributes: user.Attributes,
    username: user.Username,
    userPoolId: userPool.options.Id,
  });

  if (defineResponse.failAuthentication) {
    services.sessionStore.deleteSession(sessionId);
    throw new NotAuthorizedError();
  }

  if (defineResponse.issueTokens) {
    const userGroups = await userPool.listUserGroupMembership(ctx, user);
    const tokens = await services.tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      userPoolClient,
      req.ClientMetadata,
      "Authentication",
    );

    if (tokens.RefreshToken) {
      await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);
    }

    if (services.triggers.enabled("PostAuthentication")) {
      await services.triggers.postAuthentication(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostAuthentication_Authentication",
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
      });
    }

    services.sessionStore.deleteSession(sessionId);

    return {
      ChallengeParameters: {},
      AuthenticationResult: tokens,
    };
  }

  const challengeName: "CUSTOM_CHALLENGE" = (
    defineResponse.challengeName ?? "CUSTOM_CHALLENGE"
  ) as "CUSTOM_CHALLENGE";

  const createResponse = await services.triggers.createAuthChallenge(ctx, {
    challengeName,
    clientId: req.ClientId,
    clientMetadata: req.ClientMetadata,
    session: sessionWithResult.session,
    userAttributes: user.Attributes,
    username: user.Username,
    userPoolId: userPool.options.Id,
  });

  services.sessionStore.setChallenge(sessionId, {
    challengeName,
    privateChallengeParameters:
      createResponse.privateChallengeParameters ?? {},
    publicChallengeParameters: createResponse.publicChallengeParameters ?? {},
    expectedAnswer:
      createResponse.privateChallengeParameters?.expectedAnswer ?? null,
    challengeMetadata: createResponse.challengeMetadata || undefined,
  });

  return {
    ChallengeName: "CUSTOM_CHALLENGE",
    ChallengeParameters: createResponse.publicChallengeParameters ?? {},
    Session: encodeSessionToken(sessionId),
  };
};

export const RespondToAuthChallenge =
  ({
    clock,
    cognito,
    sessionStore,
    triggers,
    tokenGenerator,
  }: RespondToAuthChallengeService): RespondToAuthChallengeTarget =>
  async (ctx, req) => {
    if (!req.ChallengeResponses) {
      throw new InvalidParameterError(
        "Missing required parameter challenge responses",
      );
    }
    if (!req.ChallengeResponses.USERNAME) {
      throw new InvalidParameterError("Missing required parameter USERNAME");
    }
    if (!req.Session) {
      throw new InvalidParameterError("Missing required parameter Session");
    }

    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const userPoolClient = await cognito.getAppClient(ctx, req.ClientId);

    const user = await userPool.getUserByUsername(
      ctx,
      req.ChallengeResponses.USERNAME,
    );
    if (!user || !userPoolClient) {
      throw new NotAuthorizedError();
    }

    if (req.ChallengeName === "CUSTOM_CHALLENGE") {
      return customAuthChallenge(ctx, req, userPool, userPoolClient, user, {
        clock,
        cognito,
        sessionStore,
        triggers,
        tokenGenerator,
      });
    } else if (req.ChallengeName === "SMS_MFA") {
      if (user.MFACode !== req.ChallengeResponses.SMS_MFA_CODE) {
        throw new CodeMismatchError();
      }

      await userPool.saveUser(ctx, {
        ...user,
        MFACode: undefined,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "NEW_PASSWORD_REQUIRED") {
      if (!req.ChallengeResponses.NEW_PASSWORD) {
        throw new InvalidParameterError(
          "Missing required parameter NEW_PASSWORD",
        );
      }

      // TODO: validate the password?
      await userPool.saveUser(ctx, {
        ...user,
        Password: req.ChallengeResponses.NEW_PASSWORD,
        UserLastModifiedDate: clock.get(),
        UserStatus: "CONFIRMED",
      });
    } else {
      throw new UnsupportedError(
        `respondToAuthChallenge with ChallengeName=${req.ChallengeName}`,
      );
    }

    if (triggers.enabled("PostAuthentication")) {
      await triggers.postAuthentication(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostAuthentication_Authentication",
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: userPool.options.Id,
      });
    }

    const userGroups = await userPool.listUserGroupMembership(ctx, user);

    return {
      ChallengeParameters: {},
      AuthenticationResult: await tokenGenerator.generate(
        ctx,
        user,
        userGroups,
        userPoolClient,
        req.ClientMetadata,
        "Authentication",
      ),
    };
  };
