/**
 * How each audit action is presented.
 *
 * ## The distinction this file exists for
 *
 * `session.refresh_raced` and `session.reuse_detected` are the same event on the
 * wire — a refresh token presented after it was already spent — and they mean
 * opposite things. A race is two of the estate's tabs waking together, which is
 * the *expected* shape on a one-origin estate where six apps share one access
 * cookie at `Path=/`; the family survives and nothing is wrong. A reuse is a
 * replayed token whose family had no live successor: the estate's stolen-cookie
 * alarm, and the family was burned down.
 *
 * Rendering them alike destroys the signal, because the benign one happens
 * routinely and would bury the other. So `reuse_detected` is the only `alarm`
 * severity in the vocabulary and `refresh_raced` is explicitly labelled benign
 * with the reason written out — an operator who sees it should stop looking.
 *
 * ## Severities
 *
 * - `alarm` — something is wrong right now. One action qualifies.
 * - `notice` — worth reading: a failure, or the break-glass credential in use,
 *   or an app being opened to the public internet.
 * - `authority` — who can reach what changed. The rows the log exists for.
 * - `benign` — ordinary traffic. Present but quiet.
 *
 * An unknown action is `benign` and keeps its raw string as its label. The log
 * is append-only and older rows outlive the vocabulary that wrote them, so this
 * must never throw and must never hide a row it does not recognise.
 */

export type AuditSeverity = "alarm" | "notice" | "authority" | "benign";

export interface AuditActionPresentation {
  severity: AuditSeverity;
  /** A short sentence-case phrase for the table cell. */
  label: string;
  /** One sentence of what it means, shown beside the row. Empty for none. */
  explanation: string;
  /** True only for `session.reuse_detected`. Drives the alarm treatment. */
  isAlarm: boolean;
}

const ACTIONS: Record<string, Omit<AuditActionPresentation, "isAlarm">> = {
  // ---- The alarm, and its benign twin. -----------------------------------
  "session.reuse_detected": {
    severity: "alarm",
    label: "Refresh token replayed",
    explanation:
      "A spent refresh token was presented with no live successor in its family. This is the estate's stolen-cookie signal; the whole family was revoked and everyone on it has to sign in again.",
  },
  "session.refresh_raced": {
    severity: "benign",
    label: "Refresh raced",
    explanation:
      "Two tabs refreshed at the same moment. The loser presented a token the winner had just spent. The session survived and nothing was revoked — this is not a theft signal.",
  },

  // ---- Ordinary session traffic. -----------------------------------------
  "session.login": { severity: "benign", label: "Signed in", explanation: "" },
  "session.logout": { severity: "benign", label: "Signed out", explanation: "" },
  "session.login_failed": {
    severity: "notice",
    label: "Sign-in refused",
    explanation:
      "A wrong password for an account that exists. Ward does not log attempts against usernames that do not.",
  },
  "session.refresh_denied": {
    severity: "notice",
    label: "Refresh refused",
    explanation: "A refresh token was rejected — expired, revoked, or never issued.",
  },
  "session.revoke": {
    severity: "authority",
    label: "Session ended",
    explanation: "One device's session was ended from the console.",
  },
  "session.revoke_all": {
    severity: "authority",
    label: "All sessions ended",
    explanation:
      "Every live session for the account was ended in one call from the console. The account itself — its grants, password and email — was untouched.",
  },
  "session.revoke_others": {
    severity: "authority",
    label: "Other sessions signed out",
    explanation:
      "The account holder ended every session but the one they used to do it — the self-service response to a suspected stolen session.",
  },

  // ---- The break-glass credential itself. --------------------------------
  "console.login": {
    severity: "notice",
    label: "Console opened",
    explanation:
      "The break-glass credential was used. It lives in Ward's environment, cannot be revoked or rotated without a redeploy, and this log is the only record that it was used.",
  },
  "console.login.failed": {
    severity: "notice",
    label: "Console sign-in refused",
    explanation:
      "A console credential was refused. The submitted username is deliberately not recorded — there is only one, and a username field is where a mistyped password lands.",
  },
  "console.logout": { severity: "benign", label: "Console closed", explanation: "" },

  // ---- Authority. The rows the log exists for. ---------------------------
  "grant.create": {
    severity: "authority",
    label: "Grant issued",
    explanation: "An account can now reach an app it could not reach before.",
  },
  "grant.revoke": { severity: "authority", label: "Grant revoked", explanation: "" },
  "grant.revoke_app": {
    severity: "authority",
    label: "App access revoked",
    explanation: "Every role one account held in one app was removed at once.",
  },
  "user.create": {
    severity: "authority",
    label: "Account created",
    explanation: "A new account. It confers nothing until a grant is issued for it.",
  },
  "user.disable": {
    severity: "authority",
    label: "Account disabled",
    explanation:
      "The account was locked and its live sessions revoked. Its grants were left in place, so re-enabling restores exactly what was there.",
  },
  "user.enable": {
    severity: "authority",
    label: "Account re-enabled",
    explanation: "The grants came back with it. The revoked sessions did not.",
  },
  "user.password_rotate": {
    severity: "authority",
    label: "Password rotated",
    explanation:
      "The operator set a new password and every live session was revoked with it. The password itself is not recorded anywhere.",
  },
  "user.password_change": {
    severity: "authority",
    label: "Password changed (self-service)",
    explanation:
      "The account holder changed their own password after verifying the old one. Every other session ended with it; the session that made the change was rotated onto a fresh credential rather than revoked.",
  },
  "user.password_change_failed": {
    severity: "notice",
    label: "Password change refused",
    explanation:
      "The account holder tried to change their own password but gave the wrong current one. One wrong guess is not a theft signal by itself — a run of them against one account is worth a second look.",
  },
  "app.create": {
    severity: "authority",
    label: "App registered",
    explanation: "Closed to strangers and reachable by nobody until grants are issued.",
  },
  "app.delete": {
    severity: "authority",
    label: "App removed",
    explanation:
      "Every grant for the app went with it. The count in the detail is the only trace those rows existed.",
  },
  "app.update": { severity: "benign", label: "App renamed", explanation: "" },
  "app.registration": {
    severity: "notice",
    label: "Registration changed",
    explanation:
      "This is the only action in Ward that makes an app reachable by a stranger, or stops it being so. Read the detail.",
  },
};

/** Present one action. Never throws; an unrecognised action stays visible. */
export function presentAuditAction(action: string): AuditActionPresentation {
  const known = ACTIONS[action];
  if (known === undefined) {
    return { severity: "benign", label: action, explanation: "", isAlarm: false };
  }
  return { ...known, isAlarm: action === "session.reuse_detected" };
}

/** Every action the console knows how to filter by, grouped for the picker. */
export const AUDIT_ACTION_GROUPS: { group: string; actions: string[] }[] = [
  {
    group: "Sessions",
    actions: [
      "session.login",
      "session.login_failed",
      "session.logout",
      "session.refresh_denied",
      "session.refresh_raced",
      "session.reuse_detected",
      "session.revoke",
      "session.revoke_all",
      "session.revoke_others",
    ],
  },
  { group: "Console", actions: ["console.login", "console.login.failed", "console.logout"] },
  { group: "Grants", actions: ["grant.create", "grant.revoke", "grant.revoke_app"] },
  {
    group: "Accounts",
    actions: [
      "user.create",
      "user.disable",
      "user.enable",
      "user.password_rotate",
      "user.password_change",
      "user.password_change_failed",
    ],
  },
  { group: "Apps", actions: ["app.create", "app.update", "app.registration", "app.delete"] },
];

/**
 * Split a grant `target_id` back into its parts.
 *
 * `api/src/db/audit-log.ts` writes it with `grantTargetId`, which
 * **percent-encodes** each of the three parts before joining them with `:` —
 * precisely because a role is opaque and may itself contain a colon. Splitting
 * on `:` and stopping there mis-parses exactly the roles the encoding exists
 * for, so this decodes each part and refuses anything that is not three of
 * them.
 */
export function parseGrantTarget(
  targetId: string,
): { subject: string; appSlug: string; role: string } | undefined {
  const parts = targetId.split(":");
  if (parts.length !== 3) return undefined;
  try {
    const [subject, appSlug, role] = parts.map((part) => decodeURIComponent(part)) as [
      string,
      string,
      string,
    ];
    return { subject, appSlug, role };
  } catch {
    // A malformed escape such as "%zz". Better to render the raw id than throw.
    return undefined;
  }
}
