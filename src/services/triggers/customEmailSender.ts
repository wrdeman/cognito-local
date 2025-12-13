import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { CryptoService } from "../crypto";
import type {
  CustomEmailSenderTriggerResponse,
  FunctionConfig,
  Lambda,
} from "../lambda";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type CustomEmailSenderTrigger = Trigger<
  {
    code: string;
    source:
      | "CustomEmailSender_SignUp"
      | "CustomEmailSender_ResendCode"
      | "CustomEmailSender_ForgotPassword"
      | "CustomEmailSender_UpdateUserAttribute"
      | "CustomEmailSender_VerifyUserAttribute"
      | "CustomEmailSender_AdminCreateUser";
    userPoolId: string;
    clientId: string | null;
    username: string;
    userAttributes: AttributeListType;

    /**
     * One or more key-value pairs that you can provide as custom input to the Lambda function that you specify for the
     * custom message trigger. You can pass this data to your Lambda function by using the ClientMetadata parameter in the
     * following API actions:
     *
     * - AdminResetUserPassword
     * - AdminRespondToAuthChallenge
     * - AdminUpdateUserAttributes
     * - ForgotPassword
     * - GetUserAttributeVerificationCode
     * - ResendConfirmationCode
     * - SignUp
     * - UpdateUserAttributes
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-message.html#cognito-user-pools-lambda-trigger-syntax-custom-message
     */
    clientMetadata: Record<string, string> | undefined;
    lambdaConfig?: FunctionConfig;
  },
  CustomEmailSenderTriggerResponse | null
>;

interface CustomEmailSenderServices {
  lambda: Lambda;
  crypto: CryptoService;
}

export const CustomEmailSender =
  ({ lambda, crypto }: CustomEmailSenderServices): CustomEmailSenderTrigger =>
  async (
    ctx,
    {
      clientId,
      clientMetadata,
      code,
      lambdaConfig,
      source,
      userAttributes,
      username,
      userPoolId,
    },
  ) => {
    try {
      const encrypted = await crypto.encrypt(ctx, code);

      const event = {
        code: encrypted,
        clientId,
        clientMetadata,
        triggerSource: source,
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
      };

      if (lambdaConfig) {
        await lambda.invoke(ctx, "CustomEmailSender", event, lambdaConfig);
      } else {
        await lambda.invoke(ctx, "CustomEmailSender", event);
      }

      return {};
    } catch (ex) {
      ctx.logger.error(ex);
      return null;
    }
  };
