import { v4 as uuid } from "uuid";

export interface ChallengeResultItem {
  challengeName: string;
  challengeResult: boolean;
  challengeMetadata?: string;
}

export interface ChallengeState {
  challengeName: string;
  privateChallengeParameters: Record<string, string>;
  publicChallengeParameters: Record<string, string>;
  expectedAnswer: string | null;
  challengeMetadata?: string;
}

export interface AuthSession {
  id: string;
  userPoolId: string;
  clientId: string;
  username: string;
  session: ChallengeResultItem[];
  challenge?: ChallengeState;
  attempts: number;
}

export interface SessionStore {
  createSession(input: {
    clientId: string;
    userPoolId: string;
    username: string;
  }): AuthSession;
  getSession(sessionId: string): AuthSession | null;
  setChallenge(sessionId: string, challenge: ChallengeState): AuthSession;
  recordChallengeResult(sessionId: string, result: boolean): AuthSession;
  deleteSession(sessionId: string): void;
}

export class InMemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, AuthSession>();

  public createSession({ clientId, userPoolId, username }: {
    clientId: string;
    userPoolId: string;
    username: string;
  }): AuthSession {
    const id = uuid();
    const session: AuthSession = {
      id,
      userPoolId,
      clientId,
      username,
      session: [],
      attempts: 0,
    };
    this.sessions.set(id, session);
    return session;
  }

  public getSession(sessionId: string): AuthSession | null {
    return this.sessions.get(sessionId) ?? null;
  }

  public setChallenge(sessionId: string, challenge: ChallengeState): AuthSession {
    const existing = this.sessions.get(sessionId);
    if (!existing) {
      throw new Error("Invalid session");
    }

    const updated: AuthSession = {
      ...existing,
      challenge,
      attempts: existing.attempts + 1,
    };
    this.sessions.set(sessionId, updated);
    return updated;
  }

  public recordChallengeResult(sessionId: string, result: boolean): AuthSession {
    const existing = this.sessions.get(sessionId);
    if (!existing || !existing.challenge) {
      throw new Error("Invalid session");
    }

    const updated: AuthSession = {
      ...existing,
      session: [
        ...existing.session,
        {
          challengeName: existing.challenge.challengeName,
          challengeResult: result,
          challengeMetadata: existing.challenge.challengeMetadata,
        },
      ],
    };
    this.sessions.set(sessionId, updated);
    return updated;
  }

  public deleteSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

export const encodeSessionToken = (sessionId: string): string =>
  Buffer.from(sessionId, "utf-8").toString("base64");

export const decodeSessionToken = (token: string): string => {
  const decoded = Buffer.from(token, "base64").toString("utf-8");
  if (!decoded) {
    throw new Error("Invalid session token");
  }
  return decoded;
};
