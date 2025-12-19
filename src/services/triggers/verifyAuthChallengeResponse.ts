import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type {
  FunctionConfig,
  Lambda,
  VerifyAuthChallengeResponseTriggerResponse,
} from "../lambda";
import type { ChallengeResultItem } from "../sessionStore";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type VerifyAuthChallengeResponseTrigger = Trigger<
  {
    challengeAnswer: string;
    clientId: string;
    clientMetadata: Record<string, string> | undefined;
    privateChallengeParameters: Record<string, string>;
    session: ChallengeResultItem[];
    userAttributes: AttributeListType;
    username: string;
    userPoolId: string;
    lambdaConfig?: FunctionConfig;
  },
  VerifyAuthChallengeResponseTriggerResponse
>;

export const VerifyAuthChallengeResponse =
  ({ lambda }: { lambda: Lambda }): VerifyAuthChallengeResponseTrigger =>
  async (
    ctx,
    {
      challengeAnswer,
      clientId,
      clientMetadata,
      lambdaConfig,
      privateChallengeParameters,
      session,
      userAttributes,
      username,
      userPoolId,
    },
  ) =>
    lambda.invoke(
      ctx,
      "VerifyAuthChallengeResponse",
      {
        challengeAnswer,
        clientId,
        clientMetadata,
        privateChallengeParameters,
        triggerSource: "VerifyAuthChallengeResponse_Authentication",
        userAttributes: attributesToRecord(userAttributes),
        username,
        userPoolId,
      },
      lambdaConfig,
    );
