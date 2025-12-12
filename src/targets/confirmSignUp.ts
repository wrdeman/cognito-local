import type {
  ConfirmSignUpRequest,
  ConfirmSignUpResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  CodeMismatchError,
  ExpiredCodeError,
  NotAuthorizedError,
} from "../errors";
import type { Services } from "../services";
import { attribute, attributesAppend } from "../services/userPoolService";
import type { Target } from "./Target";

export type ConfirmSignUpTarget = Target<
  ConfirmSignUpRequest,
  ConfirmSignUpResponse
>;

export const ConfirmSignUp =
  ({
    cognito,
    clock,
    triggers,
  }: Pick<Services, "cognito" | "clock" | "triggers">): ConfirmSignUpTarget =>
  async (ctx, req) => {
    const isLocal = process.env.COGNITO_LOCAL === "true";
    const userPool = await cognito.getUserPoolForClientId(ctx, req.ClientId);
    const user = await userPool.getUserByUsername(ctx, req.Username);

    if (!user) {
      // AWS uses NotAuthorized to prevent enumeration
      throw new NotAuthorizedError();
    }

    if (!isLocal) {
      if (!user.ConfirmationCode) {
        throw new ExpiredCodeError();
      }

      if (user.ConfirmationCode !== req.ConfirmationCode) {
        throw new CodeMismatchError();
      }
    }

    /**
     * 🚀 LOCAL MODE PATCH:
     * Auto-confirm user regardless of stored confirmation code.
     * This matches production’s AdminCreateUser + AdminSetUserPassword flow.
     */
    const updatedUser = {
      ...user,
      UserStatus: "CONFIRMED",
      ConfirmationCode: undefined,
      UserLastModifiedDate: clock.get(),
    };

    await userPool.saveUser(ctx, updatedUser);

    // Keep PostConfirmation behavior unchanged
    if (triggers.enabled("PostConfirmation")) {
      await triggers.postConfirmation(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostConfirmation_ConfirmSignUp",
        username: updatedUser.Username,
        userPoolId: userPool.options.Id,
        userAttributes: attributesAppend(
          updatedUser.Attributes,
          attribute("cognito:user_status", updatedUser.UserStatus),
        ),
      });
    }

    return {};
  };
