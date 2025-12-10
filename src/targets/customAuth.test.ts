import { beforeEach, describe, expect, it, vi, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError } from "../errors";
import type { Triggers, UserPoolService } from "../services";
import {
  InMemorySessionStore,
  decodeSessionToken,
} from "../services/sessionStore";
import type { TokenGenerator } from "../services/tokenGenerator";
import { InitiateAuth, type InitiateAuthTarget } from "./initiateAuth";
import {
  RespondToAuthChallenge,
  type RespondToAuthChallengeTarget,
} from "./respondToAuthChallenge";

const currentDate = new Date();

describe("CUSTOM_AUTH flow", () => {
  let initiateAuth: InitiateAuthTarget;
  let respondToAuthChallenge: RespondToAuthChallengeTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockTriggers: MockedObject<Triggers>;
  let mockTokenGenerator: MockedObject<TokenGenerator>;
  let sessionStore: InMemorySessionStore;
  let clock: ClockFake;
  const userPoolClient = TDB.appClient();
  const user = TDB.user();

  beforeEach(() => {
    clock = new ClockFake(currentDate);
    mockUserPoolService = newMockUserPoolService({
      Id: userPoolClient.UserPoolId,
    });
    mockTriggers = newMockTriggers();
    mockTokenGenerator = newMockTokenGenerator();
    sessionStore = new InMemorySessionStore();

    const mockCognitoService = newMockCognitoService(mockUserPoolService);
    mockCognitoService.getAppClient.mockResolvedValue(userPoolClient);
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
    });

    initiateAuth = InitiateAuth({
      cognito: mockCognitoService,
      messages: { deliver: vi.fn() } as any,
      otp: vi.fn(),
      sessionStore,
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });

    respondToAuthChallenge = RespondToAuthChallenge({
      clock,
      cognito: mockCognitoService,
      sessionStore,
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });
  });

  const enableCustomTriggers = () =>
    mockTriggers.enabled.mockImplementation((trigger) =>
      [
        "DefineAuthChallenge",
        "CreateAuthChallenge",
        "VerifyAuthChallengeResponse",
        "PostAuthentication",
      ].includes(trigger as any),
    );

  it("completes a single round custom challenge", async () => {
    enableCustomTriggers();

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: "CUSTOM_CHALLENGE",
      issueTokens: false,
      failAuthentication: false,
    });

    mockTriggers.createAuthChallenge.mockResolvedValueOnce({
      publicChallengeParameters: { delivery: "email" },
      privateChallengeParameters: { expectedAnswer: "123456" },
      challengeMetadata: "metadata",
    });

    mockTriggers.verifyAuthChallengeResponse.mockResolvedValueOnce({
      answerCorrect: true,
    });

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: null,
      issueTokens: true,
      failAuthentication: false,
    });

    const initiateResponse = await initiateAuth(TestContext, {
      AuthFlow: "CUSTOM_AUTH",
      ClientId: userPoolClient.ClientId,
      AuthParameters: {
        USERNAME: user.Username,
      },
    });

    expect(initiateResponse.ChallengeName).toEqual("CUSTOM_CHALLENGE");
    expect(initiateResponse.Session).toBeDefined();
    expect(initiateResponse.ChallengeParameters).toEqual({ delivery: "email" });

    const respondResponse = await respondToAuthChallenge(TestContext, {
      ChallengeName: "CUSTOM_CHALLENGE",
      ClientId: userPoolClient.ClientId,
      Session: initiateResponse.Session!,
      ChallengeResponses: {
        USERNAME: user.Username,
        ANSWER: "123456",
      },
    });

    expect(respondResponse.AuthenticationResult?.AccessToken).toEqual("access");
    expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledTimes(2);
    const sessionId = decodeSessionToken(initiateResponse.Session!);
    expect(sessionStore.getSession(sessionId)).toBeNull();
  });

  it("supports multiple challenge rounds", async () => {
    enableCustomTriggers();

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: "CUSTOM_CHALLENGE",
      issueTokens: false,
      failAuthentication: false,
    });

    mockTriggers.createAuthChallenge.mockResolvedValueOnce({
      publicChallengeParameters: { attempt: "one" },
      privateChallengeParameters: { expectedAnswer: "111" },
      challengeMetadata: "round1",
    });

    mockTriggers.verifyAuthChallengeResponse.mockResolvedValueOnce({
      answerCorrect: false,
    });

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: "CUSTOM_CHALLENGE",
      issueTokens: false,
      failAuthentication: false,
    });

    mockTriggers.createAuthChallenge.mockResolvedValueOnce({
      publicChallengeParameters: { attempt: "two" },
      privateChallengeParameters: { expectedAnswer: "222" },
      challengeMetadata: "round2",
    });

    mockTriggers.verifyAuthChallengeResponse.mockResolvedValueOnce({
      answerCorrect: true,
    });

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: null,
      issueTokens: true,
      failAuthentication: false,
    });

    const initiateResponse = await initiateAuth(TestContext, {
      AuthFlow: "CUSTOM_AUTH",
      ClientId: userPoolClient.ClientId,
      AuthParameters: { USERNAME: user.Username },
    });

    const secondChallenge = await respondToAuthChallenge(TestContext, {
      ChallengeName: "CUSTOM_CHALLENGE",
      ClientId: userPoolClient.ClientId,
      Session: initiateResponse.Session!,
      ChallengeResponses: { USERNAME: user.Username, ANSWER: "000" },
    });

    expect(secondChallenge.ChallengeName).toEqual("CUSTOM_CHALLENGE");
    expect(secondChallenge.ChallengeParameters).toEqual({ attempt: "two" });

    const finalResponse = await respondToAuthChallenge(TestContext, {
      ChallengeName: "CUSTOM_CHALLENGE",
      ClientId: userPoolClient.ClientId,
      Session: secondChallenge.Session!,
      ChallengeResponses: { USERNAME: user.Username, ANSWER: "222" },
    });

    expect(finalResponse.AuthenticationResult?.IdToken).toEqual("id");
    expect(mockTriggers.verifyAuthChallengeResponse).toHaveBeenCalledTimes(2);
    expect(mockTriggers.defineAuthChallenge).toHaveBeenCalledTimes(3);
  });

  it("fails authentication when DefineAuthChallenge requests it", async () => {
    enableCustomTriggers();

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: "CUSTOM_CHALLENGE",
      issueTokens: false,
      failAuthentication: false,
    });

    mockTriggers.createAuthChallenge.mockResolvedValueOnce({
      publicChallengeParameters: {},
      privateChallengeParameters: { expectedAnswer: "123" },
    });

    mockTriggers.verifyAuthChallengeResponse.mockResolvedValueOnce({
      answerCorrect: false,
    });

    mockTriggers.defineAuthChallenge.mockResolvedValueOnce({
      challengeName: null,
      issueTokens: false,
      failAuthentication: true,
    });

    const initiateResponse = await initiateAuth(TestContext, {
      AuthFlow: "CUSTOM_AUTH",
      ClientId: userPoolClient.ClientId,
      AuthParameters: { USERNAME: user.Username },
    });

    await expect(
      respondToAuthChallenge(TestContext, {
        ChallengeName: "CUSTOM_CHALLENGE",
        ClientId: userPoolClient.ClientId,
        Session: initiateResponse.Session!,
        ChallengeResponses: { USERNAME: user.Username, ANSWER: "000" },
      }),
    ).rejects.toBeInstanceOf(NotAuthorizedError);
  });
});
