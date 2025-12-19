const SESSION_VERSION = "1";

export interface ConfirmSignUpSessionToken {
  readonly type: "ConfirmSignUp";
  readonly clientId: string;
  readonly userPoolId: string;
  readonly username: string;
  readonly version: typeof SESSION_VERSION;
}

export const encodeConfirmSignUpSession = ({
  clientId,
  userPoolId,
  username,
}: Omit<ConfirmSignUpSessionToken, "type" | "version">): string =>
  Buffer.from(
    JSON.stringify({
      type: "ConfirmSignUp",
      clientId,
      userPoolId,
      username,
      version: SESSION_VERSION,
    }),
    "utf-8",
  ).toString("base64");

export const decodeConfirmSignUpSession = (
  session?: string,
): ConfirmSignUpSessionToken | null => {
  if (!session) {
    return null;
  }

  try {
    const decoded = Buffer.from(session, "base64").toString("utf-8");
    const parsed = JSON.parse(decoded);

    if (
      parsed?.type === "ConfirmSignUp" &&
      parsed?.version === SESSION_VERSION &&
      typeof parsed.clientId === "string" &&
      typeof parsed.userPoolId === "string" &&
      typeof parsed.username === "string"
    ) {
      return parsed as ConfirmSignUpSessionToken;
    }
  } catch {
    // Fall through to return null below.
  }

  return null;
};
