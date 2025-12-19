import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type Mock,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { UUID } from "../__tests__/patterns";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
  PasswordResetRequiredError,
} from "../errors";
import type { Messages, Triggers, UserPoolService } from "../services";
import { encodeConfirmSignUpSession } from "../services/confirmSignUpSession";
import type { CryptoService } from "../services/crypto";
import { LambdaService } from "../services/lambda";
import { InMemorySessionStore } from "../services/sessionStore";
import type { TokenGenerator } from "../services/tokenGenerator";
import { TriggersService } from "../services/triggers";
import { attributesToRecord, type User } from "../services/userPoolService";
import { InitiateAuth, type InitiateAuthTarget } from "./initiateAuth";

describe("InitiateAuth target", () => {
  let initiateAuth: InitiateAuthTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockOtp: Mock<() => string>;
  let mockTriggers: MockedObject<Triggers>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let sessionStore: InMemorySessionStore;
  const userPoolClient = TDB.appClient();

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockMessages = newMockMessages();
    mockOtp = vi.fn().mockReturnValue("123456");
    mockTriggers = newMockTriggers();
    mockTokenGenerator = newMockTokenGenerator();
    sessionStore = new InMemorySessionStore();

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);

    initiateAuth = InitiateAuth({
      cognito: mockCognitoService,
      messages: mockMessages,
      otp: mockOtp,
      sessionStore,
      triggers: mockTriggers,
      tokenGenerator: mockTokenGenerator,
    });
  });

  describe("USER_PASSWORD_AUTH auth flow", () => {
    it("throws if AuthParameters not provided", async () => {
      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
        }),
      ).rejects.toEqual(
        new InvalidParameterError("Missing required parameter authParameters"),
      );
    });

    it("throws if password is incorrect", async () => {
      const user = TDB.user();

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: "bad-password",
          },
        }),
      ).rejects.toBeInstanceOf(InvalidPasswordError);
    });

    it("throws when user requires reset", async () => {
      const user = TDB.user({
        UserStatus: "RESET_REQUIRED",
      });

      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      await expect(
        initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: "bad-password",
          },
        }),
      ).rejects.toBeInstanceOf(PasswordResetRequiredError);
    });

    it("does not change USER_PASSWORD_AUTH alias handling", async () => {
      const emailAlias = "alias@example.com";
      const user = TDB.user({
        Attributes: [
          { Name: "email", Value: emailAlias },
          { Name: "sub", Value: "sub" },
        ],
        Password: "Password123!",
        Username: "canonical-username",
      });

      mockUserPoolService.options.UsernameAttributes = ["email"];
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });

      const response = await initiateAuth(TestContext, {
        ClientId: userPoolClient.ClientId,
        AuthFlow: "USER_PASSWORD_AUTH",
        AuthParameters: {
          USERNAME: emailAlias,
          PASSWORD: user.Password!,
        },
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
      expect(mockUserPoolService.listUsers).not.toHaveBeenCalled();
      expect(mockUserPoolService.getUserByUsername).toHaveBeenCalledWith(
        TestContext,
        emailAlias,
      );
    });

    describe("when user doesn't exist", () => {
      describe("when User Migration trigger is enabled", () => {
        it("invokes the User Migration trigger and continues", async () => {
          mockTokenGenerator.generate.mockResolvedValue({
            AccessToken: "access",
            IdToken: "id",
            RefreshToken: "refresh",
          });

          const user = TDB.user();

          mockTriggers.enabled.mockReturnValue(true);
          mockTriggers.userMigration.mockResolvedValue(user);
          mockUserPoolService.getUserByUsername.mockResolvedValue(null);

          const output = await initiateAuth(TestContext, {
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
            ClientId: userPoolClient.ClientId,
            ClientMetadata: {
              client: "metadata",
            },
          });

          expect(mockTriggers.userMigration).toHaveBeenCalledWith(TestContext, {
            clientId: userPoolClient.ClientId,
            clientMetadata: undefined,
            password: user.Password,
            userAttributes: [],
            userPoolId: userPoolClient.UserPoolId,
            username: user.Username,
            validationData: { client: "metadata" },
          });

          expect(output).toBeDefined();
          expect(output.AuthenticationResult?.AccessToken).toBeDefined();
        });
      });

      describe("when User Migration trigger is disabled", () => {
        it("throws", async () => {
          mockTriggers.enabled.mockReturnValue(false);
          mockUserPoolService.getUserByUsername.mockResolvedValue(null);

          await expect(
            initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: "username",
                PASSWORD: "password",
              },
            }),
          ).rejects.toBeInstanceOf(NotAuthorizedError);
        });
      });
    });

    describe("when password matches", () => {
      describe("when MFA is ON", () => {
        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "ON";
        });

        describe("when user has SMS_MFA configured", () => {
          let user: User;

          beforeEach(() => {
            user = TDB.user({
              Attributes: [
                {
                  Name: "phone_number",
                  Value: "0411000111",
                },
              ],
              MFAOptions: [
                {
                  DeliveryMedium: "SMS",
                  AttributeName: "phone_number",
                },
              ],
            });
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("sends MFA code to user", async () => {
            const output = await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
            });

            expect(output).toBeDefined();

            expect(mockMessages.deliver).toHaveBeenCalledWith(
              TestContext,
              "Authentication",
              userPoolClient.ClientId,
              userPoolClient.UserPoolId,
              user,
              "123456",
              undefined,
              {
                AttributeName: "phone_number",
                DeliveryMedium: "SMS",
                Destination: "0411000111",
              },
            );

            // also saves the code on the user for comparison later
            expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
              TestContext,
              {
                ...user,
                MFACode: "123456",
              },
            );
          });

          describe("when Post Authentication trigger is enabled", () => {
            it("does not invoke the trigger", async () => {
              mockTriggers.enabled.mockImplementation(
                (trigger) => trigger === "PostAuthentication",
              );

              await initiateAuth(TestContext, {
                ClientId: userPoolClient.ClientId,
                AuthFlow: "USER_PASSWORD_AUTH",
                AuthParameters: {
                  USERNAME: user.Username,
                  PASSWORD: user.Password,
                },
              });

              expect(mockTriggers.postAuthentication).not.toHaveBeenCalled();
            });
          });
        });

        describe("when user doesn't have MFA configured", () => {
          const user = TDB.user({ MFAOptions: undefined });

          beforeEach(() => {
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("throws an exception", async () => {
            await expect(
              initiateAuth(TestContext, {
                ClientId: userPoolClient.ClientId,
                AuthFlow: "USER_PASSWORD_AUTH",
                AuthParameters: {
                  USERNAME: user.Username,
                  PASSWORD: user.Password,
                },
              }),
            ).rejects.toBeInstanceOf(NotAuthorizedError);
          });
        });
      });

      describe("when MFA is OPTIONAL", () => {
        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "OPTIONAL";
        });

        describe("when user has SMS_MFA configured", () => {
          let user: User;

          beforeEach(() => {
            user = TDB.user({
              Attributes: [
                {
                  Name: "phone_number",
                  Value: "0411000111",
                },
              ],
              MFAOptions: [
                {
                  DeliveryMedium: "SMS",
                  AttributeName: "phone_number",
                },
              ],
            });
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("sends MFA code to user", async () => {
            const output = await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              ClientMetadata: {
                client: "metadata",
              },
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
            });

            expect(output).toBeDefined();

            expect(mockMessages.deliver).toHaveBeenCalledWith(
              TestContext,
              "Authentication",
              userPoolClient.ClientId,
              userPoolClient.UserPoolId,
              user,
              "123456",
              {
                client: "metadata",
              },
              {
                AttributeName: "phone_number",
                DeliveryMedium: "SMS",
                Destination: "0411000111",
              },
            );

            // also saves the code on the user for comparison later
            expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
              TestContext,
              {
                ...user,
                MFACode: "123456",
              },
            );
          });

          describe("when Post Authentication trigger is enabled", () => {
            it("does not invoke the trigger", async () => {
              mockTriggers.enabled.mockImplementation(
                (trigger) => trigger === "PostAuthentication",
              );

              await initiateAuth(TestContext, {
                ClientId: userPoolClient.ClientId,
                AuthFlow: "USER_PASSWORD_AUTH",
                AuthParameters: {
                  USERNAME: user.Username,
                  PASSWORD: user.Password,
                },
              });

              expect(mockTriggers.postAuthentication).not.toHaveBeenCalled();
            });
          });
        });

        describe("when user doesn't have MFA configured", () => {
          const user = TDB.user({
            MFAOptions: undefined,
          });

          beforeEach(() => {
            mockUserPoolService.getUserByUsername.mockResolvedValue(user);
          });

          it("generates tokens", async () => {
            mockTokenGenerator.generate.mockResolvedValue({
              AccessToken: "access",
              IdToken: "id",
              RefreshToken: "refresh",
            });
            mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

            const output = await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
              ClientMetadata: {
                client: "metadata",
              },
            });

            expect(output).toBeDefined();

            expect(output.AuthenticationResult?.AccessToken).toEqual("access");
            expect(output.AuthenticationResult?.IdToken).toEqual("id");
            expect(output.AuthenticationResult?.RefreshToken).toEqual(
              "refresh",
            );

            expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
              TestContext,
              user,
              [],
              userPoolClient,
              undefined,
              "Authentication",
            );
          });
        });
      });

      describe("when MFA is OFF", () => {
        const user = TDB.user();

        beforeEach(() => {
          mockUserPoolService.options.MfaConfiguration = "OFF";
          mockUserPoolService.getUserByUsername.mockResolvedValue(user);
        });

        it("generates tokens", async () => {
          mockTokenGenerator.generate.mockResolvedValue({
            AccessToken: "access",
            IdToken: "id",
            RefreshToken: "refresh",
          });
          mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

          const output = await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
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
            undefined,
            "Authentication",
          );
        });

        describe("when Post Authentication trigger is enabled", () => {
          it("invokes the trigger before generating tokens", async () => {
            mockTokenGenerator.generate.mockResolvedValue({
              AccessToken: "access",
              IdToken: "id",
              RefreshToken: "refresh",
            });

            mockTriggers.enabled.mockImplementation(
              (trigger) => trigger === "PostAuthentication",
            );

            await initiateAuth(TestContext, {
              ClientId: userPoolClient.ClientId,
              AuthFlow: "USER_PASSWORD_AUTH",
              AuthParameters: {
                USERNAME: user.Username,
                PASSWORD: user.Password,
              },
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

            expect(mockTriggers.postAuthentication).toHaveBeenCalledBefore(
              mockTokenGenerator.generate,
            );
          });
        });
      });
    });

    describe("when user status is FORCE_CHANGE_PASSWORD", () => {
      const user = TDB.user({
        UserStatus: "FORCE_CHANGE_PASSWORD",
      });

      beforeEach(() => {
        mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      });

      it("responds with a NEW_PASSWORD_REQUIRED challenge", async () => {
        const response = await initiateAuth(TestContext, {
          ClientId: userPoolClient.ClientId,
          AuthFlow: "USER_PASSWORD_AUTH",
          AuthParameters: {
            USERNAME: user.Username,
            PASSWORD: "bad-password",
          },
        });

        expect(response).toEqual({
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            requiredAttributes: "[]",
            userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
          },
          Session: expect.stringMatching(UUID),
        });
      });

      describe("when Post Authentication trigger is enabled", () => {
        it("does not invoke the trigger", async () => {
          mockTriggers.enabled.mockImplementation(
            (trigger) => trigger === "PostAuthentication",
          );

          await initiateAuth(TestContext, {
            ClientId: userPoolClient.ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: {
              USERNAME: user.Username,
              PASSWORD: user.Password,
            },
          });

          expect(mockTriggers.postAuthentication).not.toHaveBeenCalled();
        });
      });
    });
  });

  describe("REFRESH_TOKEN_AUTH auth flow", () => {
    it("returns new tokens", async () => {
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });

      const existingUser = TDB.user({
        RefreshTokens: ["refresh token"],
      });

      mockUserPoolService.getUserByRefreshToken.mockResolvedValue(existingUser);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);

      const response = await initiateAuth(TestContext, {
        AuthFlow: "REFRESH_TOKEN_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: {
          REFRESH_TOKEN: "refresh token",
        },
        ClientMetadata: {
          client: "metadata",
        },
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
      expect(response.AuthenticationResult?.IdToken).toEqual("id");

      // does not return a refresh token as part of a refresh token flow
      expect(response.AuthenticationResult?.RefreshToken).not.toBeDefined();

      expect(mockTokenGenerator.generate).toHaveBeenCalledWith(
        TestContext,
        existingUser,
        [],
        userPoolClient,
        undefined,
        "RefreshTokens",
      );
    });
  });

  describe("CUSTOM_AUTH trigger configuration", () => {
    it("uses LambdaConfig ARNs and normalizes function names", async () => {
      const lambdaConfig = {
        DefineAuthChallenge:
          "arn:aws:lambda:us-east-1:000000000000:function:define-auth",
        CreateAuthChallenge:
          "arn:aws:lambda:us-east-1:000000000000:function:create-auth",
        VerifyAuthChallengeResponse:
          "arn:aws:lambda:us-east-1:000000000000:function:verify-auth",
      } as const;
      const userEmail = "alias@example.com";
      const user = TDB.user({
        Attributes: [
          { Name: "email", Value: userEmail },
          { Name: "sub", Value: "sub" },
        ],
        Username: "user-id",
      });

      mockUserPoolService.options.UsernameAttributes = ["email"];
      mockUserPoolService.options.LambdaConfig = lambdaConfig;
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUsers.mockResolvedValue([user]);

      const mockLambdaClient = {
        invoke: vi.fn(({ FunctionName }) => {
          const payload =
            FunctionName === "define-auth"
              ? {
                  response: {
                    challengeName: "CUSTOM_CHALLENGE",
                    failAuthentication: false,
                    issueTokens: false,
                  },
                }
              : {
                  response: {
                    privateChallengeParameters: { expectedAnswer: "123456" },
                    publicChallengeParameters: { question: "otp" },
                  },
                };

          return {
            promise: () =>
              Promise.resolve({
                StatusCode: 200,
                Payload: JSON.stringify(payload),
              }),
          };
        }),
      } as any;

      const cognitoService = newMockCognitoService(mockUserPoolService);
      cognitoService.getAppClient.mockResolvedValue(userPoolClient);

      const triggers = new TriggersService(
        new ClockFake(),
        cognitoService,
        new LambdaService({}, mockLambdaClient),
        {} as unknown as CryptoService,
      );

      initiateAuth = InitiateAuth({
        cognito: cognitoService,
        messages: mockMessages,
        otp: mockOtp,
        sessionStore,
        triggers,
        tokenGenerator: mockTokenGenerator,
      });

      const response = await initiateAuth(TestContext, {
        AuthFlow: "CUSTOM_AUTH",
        ClientId: userPoolClient.ClientId,
        AuthParameters: {
          USERNAME: userEmail,
        },
      });

      expect(triggers.enabled("DefineAuthChallenge", lambdaConfig)).toBe(true);
      expect(triggers.enabled("CreateAuthChallenge", lambdaConfig)).toBe(true);
      expect(
        triggers.enabled("VerifyAuthChallengeResponse", lambdaConfig),
      ).toBe(true);

      expect(mockLambdaClient.invoke).toHaveBeenCalledWith(
        expect.objectContaining({ FunctionName: "define-auth" }),
      );
      expect(mockLambdaClient.invoke).toHaveBeenCalledWith(
        expect.objectContaining({ FunctionName: "create-auth" }),
      );
      expect(response.ChallengeName).toEqual("CUSTOM_CHALLENGE");
    });
  });

  describe("USER_AUTH auth flow", () => {
    afterEach(() => {
      delete process.env.COGNITO_LOCAL_ENABLE_USER_AUTH_CONFIRM_SESSION;
    });

    it("returns SELECT_CHALLENGE by default even with a confirm session", async () => {
      const user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);

      const session = encodeConfirmSignUpSession({
        clientId: userPoolClient.ClientId,
        userPoolId: userPoolClient.UserPoolId,
        username: user.Username,
      });

      const response = await initiateAuth(TestContext, {
        AuthFlow: "USER_AUTH",
        AuthParameters: {
          USERNAME: user.Username,
        },
        ClientId: userPoolClient.ClientId,
        Session: session,
      });

      expect(response.ChallengeName).toEqual("SELECT_CHALLENGE");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("short-circuits to password auth when the flag is enabled", async () => {
      process.env.COGNITO_LOCAL_ENABLE_USER_AUTH_CONFIRM_SESSION = "true";

      const user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });

      const session = encodeConfirmSignUpSession({
        clientId: userPoolClient.ClientId,
        userPoolId: userPoolClient.UserPoolId,
        username: user.Username,
      });

      const response = await initiateAuth(TestContext, {
        AuthFlow: "USER_AUTH",
        AuthParameters: {
          USERNAME: user.Username,
        },
        ClientId: userPoolClient.ClientId,
        Session: session,
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    });

    it("still returns SELECT_CHALLENGE when the flag is enabled but no session is provided", async () => {
      process.env.COGNITO_LOCAL_ENABLE_USER_AUTH_CONFIRM_SESSION = "true";

      const response = await initiateAuth(TestContext, {
        AuthFlow: "USER_AUTH",
        AuthParameters: {
          USERNAME: "user", // USERNAME is still required by the flow
          PASSWORD: "Password123!",
        },
        ClientId: userPoolClient.ClientId,
      });

      expect(response.ChallengeName).toEqual("SELECT_CHALLENGE");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("returns SELECT_CHALLENGE when the provided session is not from ConfirmSignUp", async () => {
      process.env.COGNITO_LOCAL_ENABLE_USER_AUTH_CONFIRM_SESSION = "true";

      const response = await initiateAuth(TestContext, {
        AuthFlow: "USER_AUTH",
        AuthParameters: {
          USERNAME: "user",
          PASSWORD: "Password123!",
        },
        ClientId: userPoolClient.ClientId,
        Session: Buffer.from("not-a-confirm-session", "utf-8").toString(
          "base64",
        ),
      });

      expect(response.ChallengeName).toEqual("SELECT_CHALLENGE");
      expect(response.AuthenticationResult).toBeUndefined();
    });

    it("does not affect other flows", async () => {
      process.env.COGNITO_LOCAL_ENABLE_USER_AUTH_CONFIRM_SESSION = "true";

      const user = TDB.user();
      mockUserPoolService.getUserByUsername.mockResolvedValue(user);
      mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
      mockTokenGenerator.generate.mockResolvedValue({
        AccessToken: "access",
        IdToken: "id",
        RefreshToken: "refresh",
      });

      const response = await initiateAuth(TestContext, {
        AuthFlow: "USER_PASSWORD_AUTH",
        AuthParameters: {
          USERNAME: user.Username,
          PASSWORD: user.Password!,
        },
        ClientId: userPoolClient.ClientId,
      });

      expect(response.AuthenticationResult?.AccessToken).toEqual("access");
    });
  });
});
