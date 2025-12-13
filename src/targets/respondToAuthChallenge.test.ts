import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { Triggers, UserPoolService } from "../services";
import {
  InMemorySessionStore,
  encodeSessionToken,
} from "../services/sessionStore";
import type { TokenGenerator } from "../services/tokenGenerator";
import {
  RespondToAuthChallenge,
  type RespondToAuthChallengeTarget,
} from "./respondToAuthChallenge";

const currentDate = new Date();

describe("RespondToAuthChallenge target", () => {
  let respondToAuthChallenge: RespondToAuthChallengeTarget;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let mockTriggers: MockedObject<Triggers>;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let sessionStore: InMemorySessionStore;
  let clock: ClockFake;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    clock = new ClockFake(currentDate);
    mockTokenGenerator = newMockTokenGenerator();
    mockTriggers = newMockTriggers();
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    sessionStore = new InMemorySessionStore();

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    respondToAuthChallenge = RespondToAuthChallenge({
      clock,
      cognito: mockCognitoService,
      sessionStore,
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });
  });

  it("throws if user doesn't exist", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: "clientId",
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {
          USERNAME: "username",
          SMS_MFA_CODE: "123456",
        },
        Session: "Session",
      }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });

  it("throws if ChallengeResponses missing", async () => {
    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: "clientId",
        ChallengeName: "SMS_MFA",
      }),
    ).rejects.toEqual(
      new InvalidParameterError(
        "Missing required parameter challenge responses",
      ),
    );
  });

  it("throws if ChallengeResponses.USERNAME is missing", async () => {
    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: "clientId",
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {},
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Missing required parameter USERNAME"),
    );
  });

  it("throws if Session is missing", async () => {
    // we don't actually do anything with the session right now, but we still want to
    // replicate Cognito's behaviour if you don't provide it
    await expect(
      respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "SMS_MFA",
        ChallengeResponses: {
          USERNAME: "abc",
        },
      }),
    ).rejects.toEqual(
      new InvalidParameterError("Missing required parameter Session"),
    );
  });

  describe("ChallengeName=SMS_MFA", () => {
    const user = TDB.user({
      MFACode: "123456",
    });

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    describe("when code matches", () => {
      it("updates the user and removes the MFACode", async () => {
        const newDate = clock.advanceBy(1200);

        await respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "SMS_MFA",
          ChallengeResponses: {
            USERNAME: user.Username,
            SMS_MFA_CODE: "123456",
          },
          Session: "Session",
        });

        expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
          ...user,
          MFACode: undefined,
          UserLastModifiedDate: newDate,
        });
      });

      it("generates tokens", async () => {
        mockTokenGenerator.generate.mockResolvedValue({
          AccessToken: "access",
          IdToken: "id",
          RefreshToken: "refresh",
        });
        mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

        const output = await respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "SMS_MFA",
          ChallengeResponses: {
            USERNAME: user.Username,
            SMS_MFA_CODE: "123456",
          },
          Session: "Session",
          ClientMetadata: {
            client: "metadata",
          },
        });

        expect(output).toBeDefined();

        expect(output.AuthenticationResult?.AccessToken).toEqual("access");
        expect(output.AuthenticationResult?.IdToken).toEqual("id");
        expect(output.AuthenticationResult?.RefreshToken).toEqual("refresh");

        expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
          TestContext,
          user,
          [],
          userPoolClient,
          {
            client: "metadata",
          },
          "Authentication",
        );
      });

      describe("when Post Authentication trigger is enabled", () => {
        it("does invokes the trigger", async () => {
          mockTriggers.enabled.mockImplementation(
            (trigger) => trigger === "PostAuthentication",
          );

          await respondToAuthChallenge(TestContext, {
            ClientId: userPoolClient.ClientId,
            ChallengeName: "SMS_MFA",
            ClientMetadata: {
              client: "metadata",
            },
            ChallengeResponses: {
              USERNAME: user.Username,
              SMS_MFA_CODE: "123456",
            },
            Session: "Session",
          });

          expect(mockTriggers.postAuthentication).toHaveBeenCalledWith(
            TestContext,
            {
              clientId: userPoolClient.ClientId,
              clientMetadata: {
                client: "metadata",
              },
              source: "PostAuthentication_Authentication",
              userAttributes: user.Attributes,
              username: user.Username,
              userPoolId: userPoolClient.UserPoolId,
            },
          );
        });
      });
    });

    describe("when code is incorrect", () => {
      it("throws an error", async () => {
        mockUserPoolService.getUserByUsername.mockResolvedValue(user);

        await expect(
          respondToAuthChallenge(TestContext, {
            ClientId: userPoolClient.ClientId,
            ChallengeName: "SMS_MFA",
            ChallengeResponses: {
              USERNAME: user.Username,
              SMS_MFA_CODE: "4321",
            },
            Session: "Session",
          }),
        ).rejects.toBeInstanceOf(CodeMismatchError);
      });
    });
  });

  describe("ChallengeName=NEW_PASSWORD_REQUIRED", () => {
    const user = TDB.user();

    beforeEach(() => {
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    });

    it("throws if NEW_PASSWORD missing", async () => {
      await expect(
        respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeResponses: {
            USERNAME: user.Username,
          },
          Session: "session",
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Missing required parameter NEW_PASSWORD"),
      );
    });

    it("updates the user's password and status", async () => {
      const newDate = clock.advanceBy(1200);

      await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ChallengeResponses: {
          USERNAME: user.Username,
          NEW_PASSWORD: "foo",
        },
        Session: "Session",
      });

      expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
        ...user,
        Password: "foo",
        UserLastModifiedDate: newDate,
        UserStatus: "CONFIRMED",
      });
    });

    it("generates tokens", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

      const output = await respondToAuthChallenge(TestContext, {
        ClientId: userPoolClient.ClientId,
        ChallengeName: "NEW_PASSWORD_REQUIRED",
        ChallengeResponses: {
          USERNAME: user.Username,
          NEW_PASSWORD: "foo",
        },
        Session: "Session",
        ClientMetadata: {
          client: "metadata",
        },
      });

      expect(output).toBeDefined();

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
      expect(output.AuthenticationResult?.IdToken).toEqual("id");
      expect(output.AuthenticationResult?.RefreshToken).toEqual("refresh");

      expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
        TestContext,
        user,
        [],
        userPoolClient,
        { client: "metadata" },
        "Authentication",
      );
    });

    describe("when Post Authentication trigger is enabled", () => {
      it("does invokes the trigger", async () => {
        mockTriggers.enabled.mockImplementation(
          (trigger) => trigger === "PostAuthentication",
        );

        await respondToAuthChallenge(TestContext, {
          ClientId: userPoolClient.ClientId,
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeResponses: {
            USERNAME: user.Username,
            NEW_PASSWORD: "foo",
          },
          Session: "Session",
        });

        expect(mockTriggers.postAuthentication).toHaveBeenCalledWith(
          TestContext,
          {
            clientId: userPoolClient.ClientId,
            source: "PostAuthentication_Authentication",
            userAttributes: user.Attributes,
            username: user.Username,
            userPoolId: userPoolClient.UserPoolId,
          },
        );
      });
    });
  });

  describe("ChallengeName=CUSTOM_CHALLENGE", () => {
    const user = TDB.user();
    const lambdaConfig = {
      CreateAuthChallenge: "create",
      DefineAuthChallenge: "define",
      VerifyAuthChallengeResponse: "verify",
    } as const;

    beforeEach(() => {
      mockUserPoolService.options.LambdaConfig = lambdaConfig;
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });
      mockTriggers.enabled.mockImplementation(
        (trigger, poolLambdaConfig) => !!poolLambdaConfig?.[trigger],
      );
    });

    const createSessionWithChallenge = () => {
      const session = sessionStore.createSession({
        clientId: userPoolClient.ClientId,
        userPoolId: userPoolClient.UserPoolId,
        username: user.Username,
      });

      sessionStore.setChallenge(session.id, {
        challengeName: "CUSTOM_CHALLENGE",
        challengeMetadata: "metadata",
        expectedAnswer: "123456",
        privateChallengeParameters: { expectedAnswer: "123456" },
        publicChallengeParameters: {},
      });

      return session;
    };

    it("completes custom auth when triggers are configured on the pool", async () => {
      mockTriggers.verifyAuthChallengeResponse.mockResolvedValueOnce({
        answerCorrect: true,
      });
      mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
        challengeName: null,
        failAuthentication: false,
        issueTokens: true,
      });

      const session = createSessionWithChallenge();

      const output = await respondToAuthChallenge(TestContext, {
        ChallengeName: "CUSTOM_CHALLENGE",
        ChallengeResponses: {
          ANSWER: "123456",
          USERNAME: user.Username,
        },
        ClientId: userPoolClient.ClientId,
        Session: encodeSessionToken(session.id),
      });

      expect(output.AuthenticationResult?.AccessToken).toEqual("access");
      expect(mockTriggers.verifyAuthChallengeResponse).toHaveBeenCalled();
      expect(mockTriggers.defineAuthChallenge).toHaveBeenCalled();
    });

    it("fails authentication when the OTP is wrong", async () => {
      mockTriggers.verifyAuthChallengeResponse.mockResolvedValueOnce({
        answerCorrect: false,
      });
      mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
        challengeName: null,
        failAuthentication: true,
        issueTokens: false,
      });

      const session = createSessionWithChallenge();

      await expect(
        respondToAuthChallenge(TestContext, {
          ChallengeName: "CUSTOM_CHALLENGE",
          ChallengeResponses: {
            ANSWER: "000000",
            USERNAME: user.Username,
          },
          ClientId: userPoolClient.ClientId,
          Session: encodeSessionToken(session.id),
        }),
      ).rejects.toBeInstanceOf(NotAuthorizedError);
    });

    it("rejects custom auth when triggers are missing", async () => {
      mockUserPoolService.options.LambdaConfig = {};
      mockTriggers.enabled.mockReturnValue(false);

      const session = createSessionWithChallenge();

      await expect(
        respondToAuthChallenge(TestContext, {
          ChallengeName: "CUSTOM_CHALLENGE",
          ChallengeResponses: {
            ANSWER: "123456",
            USERNAME: user.Username,
          },
          ClientId: userPoolClient.ClientId,
          Session: encodeSessionToken(session.id),
        }),
      ).rejects.toEqual(
        new UnsupportedError("CUSTOM_AUTH triggers not configured"),
      );
    });
  });
});
