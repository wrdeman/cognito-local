import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Lambda, VerifyAuthChallengeResponseTriggerResponse } from "../lambda";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type VerifyAuthChallengeResponseTrigger = Trigger<
  {
    challengeAnswer: string;
    clientId: string;
    clientMetadata: Record<string, string> | undefined;
    privateChallengeParameters: Record<string, string>;
    session: readonly {
      challengeName: string;
      challengeResult: boolean;
      challengeMetadata?: string;
    }[];
    userAttributes: AttributeListType;
    username: string;
    userPoolId: string;
  },
  VerifyAuthChallengeResponseTriggerResponse
>;

export const VerifyAuthChallengeResponse = ({
  lambda,
}: {
  lambda: Lambda;
}): VerifyAuthChallengeResponseTrigger =>
  async (
    ctx,
    {
      challengeAnswer,
      clientId,
      clientMetadata,
      privateChallengeParameters,
      session,
      userAttributes,
      username,
      userPoolId,
    },
  ) =>
    lambda.invoke(ctx, "VerifyAuthChallengeResponse", {
      challengeAnswer,
      clientId,
      clientMetadata,
      privateChallengeParameters,
      session,
      triggerSource: "VerifyAuthChallengeResponse_Authentication",
      userAttributes: attributesToRecord(userAttributes),
      username,
      userPoolId,
    });
