import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type {
  DefineAuthChallengeTriggerResponse,
  FunctionConfig,
  Lambda,
} from "../lambda";
import type { ChallengeResultItem } from "../sessionStore";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type DefineAuthChallengeTrigger = Trigger<
  {
    clientId: string;
    clientMetadata: Record<string, string> | undefined;
    session: ChallengeResultItem[];
    userAttributes: AttributeListType;
    username: string;
    userPoolId: string;
    lambdaConfig?: FunctionConfig;
  },
  DefineAuthChallengeTriggerResponse
>;

export const DefineAuthChallenge =
  ({ lambda }: { lambda: Lambda }): DefineAuthChallengeTrigger =>
  async (
    ctx,
    {
      clientId,
      clientMetadata,
      lambdaConfig,
      session,
      userAttributes,
      username,
      userPoolId,
    },
  ) =>
    lambda.invoke(
      ctx,
      "DefineAuthChallenge",
      {
        clientId,
        clientMetadata,
        session,
        triggerSource: "DefineAuthChallenge_Authentication",
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
      },
      lambdaConfig,
    );
