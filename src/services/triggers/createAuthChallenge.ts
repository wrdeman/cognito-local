import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type {
  CreateAuthChallengeTriggerResponse,
  FunctionConfig,
  Lambda,
} from "../lambda";
import type { ChallengeResultItem } from "../sessionStore";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type CreateAuthChallengeTrigger = Trigger<
  {
    challengeName: string;
    clientId: string;
    clientMetadata: Record<string, string> | undefined;
    session: ChallengeResultItem[];
    userAttributes: AttributeListType;
    username: string;
    userPoolId: string;
    lambdaConfig?: FunctionConfig;
  },
  CreateAuthChallengeTriggerResponse
>;

export const CreateAuthChallenge =
  ({ lambda }: { lambda: Lambda }): CreateAuthChallengeTrigger =>
  async (
    ctx,
    {
      challengeName,
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
      "CreateAuthChallenge",
      {
        challengeName,
        clientId,
        clientMetadata,
        session,
        triggerSource: "CreateAuthChallenge_Authentication",
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
      },
      lambdaConfig,
    );
