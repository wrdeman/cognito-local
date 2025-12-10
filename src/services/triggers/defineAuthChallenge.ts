import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type { Lambda, DefineAuthChallengeTriggerResponse } from "../lambda";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type DefineAuthChallengeTrigger = Trigger<
  {
    clientId: string;
    clientMetadata: Record<string, string> | undefined;
    session: readonly {
      challengeName: string;
      challengeResult: boolean;
      challengeMetadata?: string;
    }[];
    userAttributes: AttributeListType;
    username: string;
    userPoolId: string;
  },
  DefineAuthChallengeTriggerResponse
>;

export const DefineAuthChallenge = ({
  lambda,
}: {
  lambda: Lambda;
}): DefineAuthChallengeTrigger =>
  async (
    ctx,
    { clientId, clientMetadata, session, userAttributes, username, userPoolId },
  ) =>
    lambda.invoke(ctx, "DefineAuthChallenge", {
      clientId,
      clientMetadata,
      session,
      triggerSource: "DefineAuthChallenge_Authentication",
      userAttributes: attributesToRecord(userAttributes),
      username,
      userPoolId,
    });
