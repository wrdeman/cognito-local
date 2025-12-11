import type { AttributeListType } from "aws-sdk/clients/cognitoidentityserviceprovider";
import type {
  CreateAuthChallengeTriggerResponse,
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
  },
  CreateAuthChallengeTriggerResponse
>;

export const CreateAuthChallenge = ({
  lambda,
}: {
  lambda: Lambda;
}): CreateAuthChallengeTrigger =>
  async (
    ctx,
    {
      challengeName,
      clientId,
      clientMetadata,
      session,
      userAttributes,
      username,
      userPoolId,
    },
  ) =>
    lambda.invoke(ctx, "CreateAuthChallenge", {
      challengeName,
      clientId,
      clientMetadata,
      session,
      triggerSource: "CreateAuthChallenge_Authentication",
      userAttributes: attributesToRecord(userAttributes),
      username,
      userPoolId,
    });
