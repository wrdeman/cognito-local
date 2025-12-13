import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { FunctionConfig, Lambda } from "../lambda";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type PostAuthenticationTrigger = Trigger<
  {
    clientId: string;
    /**
     * One or more key-value pairs that you can provide as custom input to the Lambda function that you specify for the
     * post authentication trigger. You can pass this data to your Lambda function by using the ClientMetadata parameter
     * in the AdminRespondToAuthChallenge and RespondToAuthChallenge API actions.
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-authentication.html
     */
    clientMetadata: Record<string, string> | undefined;
    source: "PostAuthentication_Authentication";
    userAttributes: AttributeListType;
    username: string;
    userPoolId: string;
    lambdaConfig?: FunctionConfig;
  },
  void
>;

type PostAuthenticationServices = {
  lambda: Lambda;
};

export const PostAuthentication =
  ({ lambda }: PostAuthenticationServices): PostAuthenticationTrigger =>
  async (
    ctx,
    {
      clientId,
      clientMetadata,
      lambdaConfig,
      source,
      userAttributes,
      username,
      userPoolId,
    },
  ) => {
    try {
      const event = {
        clientId,
        clientMetadata,
        triggerSource: source,
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
      };

      if (lambdaConfig) {
        await lambda.invoke(ctx, "PostAuthentication", event, lambdaConfig);
      } else {
        await lambda.invoke(ctx, "PostAuthentication", event);
      }
    } catch (err) {
      ctx.logger.warn(err, "PostAuthentication error, ignored");
    }
  };
