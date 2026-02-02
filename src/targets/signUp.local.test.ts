import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockedObject,
  vi,
} from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockMessages } from "../__tests__/mockMessages";
import { newMockTokenGenerator } from "../__tests__/mockTokenGenerator";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { DefaultConfig } from "../server/config";
import type { Messages, Triggers, UserPoolService } from "../services";
import { InMemorySessionStore } from "../services/sessionStore";
import type { User } from "../services/userPoolService";
import { InitiateAuth } from "./initiateAuth";
import { SignUp, type SignUpTarget } from "./signUp";

describe("SignUp target in local mode", () => {
  let signUp: SignUpTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;
  let mockMessages: MockedObject<Messages>;
  let mockTriggers: MockedObject<Triggers>;
  let originalLocalEnv: string | undefined;

  beforeEach(() => {
    originalLocalEnv = process.env.COGNITO_LOCAL;
    process.env.COGNITO_LOCAL = "true";

    mockUserPoolService = newMockUserPoolService();
    mockMessages = newMockMessages();
    mockTriggers = newMockTriggers();

    signUp = SignUp({
      cognito: newMockCognitoService(mockUserPoolService),
      clock: new ClockFake(new Date(2020, 1, 2, 3, 4, 5)),
      messages: mockMessages,
      otp: vi.fn(),
      config: DefaultConfig,
      triggers: mockTriggers,
    });
  });

  afterEach(() => {
    if (originalLocalEnv === undefined) {
      delete process.env.COGNITO_LOCAL;
    } else {
      process.env.COGNITO_LOCAL = originalLocalEnv;
    }
  });

  it("auto-confirms local users and verifies email without code delivery", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    const response = await signUp(TestContext, {
      ClientId: "clientId",
      Password: "Password123!",
      Username: "user",
      UserAttributes: [{ Name: "email", Value: "user@example.com" }],
    });

    expect(response.UserConfirmed).toBe(true);
    expect(response.CodeDeliveryDetails).toBeUndefined();

    const savedUser = mockUserPoolService.saveUser.mock.calls[0]?.[1];
    expect(savedUser?.UserStatus).toBe("CONFIRMED");
    expect(savedUser?.Attributes).toEqual(
      expect.arrayContaining([
        { Name: "email", Value: "user@example.com" },
        { Name: "email_verified", Value: "true" },
      ]),
    );

    expect(mockTriggers.postConfirmation).not.toHaveBeenCalled();
  });

  it("allows immediate authentication after local sign up", async () => {
    let savedUser: User | undefined;

    mockUserPoolService.saveUser.mockImplementation(async (_ctx, user) => {
      savedUser = user;
    });

    mockUserPoolService.getUserByUsername.mockImplementation(
      async (_ctx, username) => {
        if (!savedUser) {
          return null;
        }

        if (savedUser.Username === username) {
          return savedUser;
        }

        const email = savedUser.Attributes.find(
          (attribute) => attribute.Name === "email",
        )?.Value;

        return email === username ? savedUser : null;
      },
    );

    mockUserPoolService.listUserGroupMembership.mockResolvedValue([]);
    mockUserPoolService.storeRefreshToken.mockResolvedValue();

    const appClient = TDB.appClient({ ClientId: "clientId" });
    const mockCognito = newMockCognitoService(mockUserPoolService);
    mockCognito.getAppClient.mockResolvedValue(appClient);

    const mockTokenGenerator = newMockTokenGenerator();
    mockTokenGenerator.generate.mockResolvedValue({
      AccessToken: "access",
      IdToken: "id",
      RefreshToken: "refresh",
    });

    const authInitiate = InitiateAuth({
      cognito: mockCognito,
      messages: mockMessages,
      otp: vi.fn(),
      sessionStore: new InMemorySessionStore(),
      tokenGenerator: mockTokenGenerator,
      triggers: mockTriggers,
    });

    await signUp(TestContext, {
      ClientId: appClient.ClientId,
      Password: "Password123!",
      Username: "user",
      UserAttributes: [{ Name: "email", Value: "user@example.com" }],
    });

    const response = await authInitiate(TestContext, {
      AuthFlow: "USER_PASSWORD_AUTH",
      AuthParameters: {
        USERNAME: "user",
        PASSWORD: "Password123!",
      },
      ClientId: appClient.ClientId,
    });

    expect(response.AuthenticationResult?.AccessToken).toBe("access");
  });
});
