import { FormEvent, useEffect, useState } from "react";
import {
  accountApi,
  DriverApplication,
  DriverVehicleType,
  MfaEnrollment,
  UserProfile,
} from "./client";

type Page =
  | "login"
  | "register"
  | "forgot"
  | "verify"
  | "reset"
  | "mfa"
  | "mfa-setup"
  | "mfa-recovery"
  | "onboarding";

function currentPage(): Page {
  const path = window.location.hash.split("?")[0].replace(/^#\/?/, "");
  const known: Page[] = [
    "login", "register", "forgot", "verify", "reset",
    "mfa", "mfa-setup", "mfa-recovery", "onboarding",
  ];
  return known.includes(path as Page) ? (path as Page) : "login";
}

function tokenFromHash(): string {
  return new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("token") ?? "";
}

function driverVehicleType(form: FormData): DriverVehicleType {
  switch (form.get("vehicleType")) {
    case "BICYCLE": return "BICYCLE";
    case "MOTORCYCLE": return "MOTORCYCLE";
    case "CAR": return "CAR";
    case "VAN": return "VAN";
    default: throw new Error("Select a vehicle type.");
  }
}

export default function App() {
  const [page, setPage] = useState<Page>(currentPage);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [user, setUser] = useState<UserProfile | null>(null);
  const [busy, setBusy] = useState(false);
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [driverApplication, setDriverApplication] = useState<DriverApplication | null>(null);
  const [driverApplicationLoaded, setDriverApplicationLoaded] = useState(false);
  const [adminApplications, setAdminApplications] = useState<DriverApplication[]>([]);

  useEffect(() => {
    const changePage = () => {
      setPage(currentPage());
      setNotice("");
      setError("");
    };
    window.addEventListener("hashchange", changePage);
    if (page === "verify") {
      void perform(() => accountApi.verifyEmail(tokenFromHash()), "Email verified. You can now sign in.");
    }
    if (page === "onboarding") {
      setDriverApplicationLoaded(false);
      void accountApi.me().then(async (profile) => {
        setUser(profile);
        if (profile.roles.includes("CUSTOMER")) {
          setDriverApplication((await accountApi.driverApplication()) ?? null);
        }
        if (profile.roles.includes("ADMIN")) {
          setAdminApplications(await accountApi.driverApplicationsForReview());
        }
        setDriverApplicationLoaded(true);
      }).catch((cause: Error) => {
        setDriverApplicationLoaded(true);
        setError(cause.message);
      });
    }
    if (page === "mfa-setup") {
      void accountApi.beginMfaEnrollment()
        .then(setEnrollment)
        .catch((cause: Error) => setError(cause.message));
    }
    return () => window.removeEventListener("hashchange", changePage);
  }, [page]);

  async function perform(action: () => Promise<unknown>, success: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      setNotice(success);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The request could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>, action: (form: FormData) => Promise<void>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await action(form);
  }

  return (
    <main className="shell">
      <header className="brand">
        <a href="#/login" aria-label="Routevo home">routevo</a>
        <span>Local delivery, made clear.</span>
      </header>
      <section className="panel" aria-live="polite">
        {page === "login" && (
          <>
            <h1>Welcome back</h1>
            <p>Sign in to your Routevo account.</p>
            <form onSubmit={(event) => void submit(event, async (form) => {
              await perform(
                async () => {
                  const result = await accountApi.login(
                    String(form.get("email")),
                    String(form.get("password")),
                  );
                  if (result.stage === "MFA_SETUP_REQUIRED") {
                    window.location.hash = "#/mfa-setup";
                    return;
                  }
                  if (result.stage === "MFA_REQUIRED") {
                    window.location.hash = "#/mfa";
                    return;
                  }
                  setUser(await accountApi.me());
                  window.location.hash = "#/onboarding";
                },
                "Signed in.",
              );
            })}>
              <label>Email<input name="email" type="email" autoComplete="email" required /></label>
              <label>Password<input name="password" type="password" autoComplete="current-password" required /></label>
              <button disabled={busy}>{busy ? "Signing in..." : "Sign in"}</button>
            </form>
            <nav><a href="#/register">Create account</a><a href="#/forgot">Forgot password?</a></nav>
          </>
        )}
        {page === "register" && (
          <>
            <h1>Create your account</h1>
            <p>We will email you a verification link before sign-in is enabled.</p>
            <form onSubmit={(event) => void submit(event, async (form) => {
              await perform(
                () => accountApi.register(
                  String(form.get("name")),
                  String(form.get("email")),
                  String(form.get("phone") ?? ""),
                  String(form.get("password")),
                ),
                "If this address can be registered, a verification email will arrive shortly.",
              );
            })}>
              <label>Full name<input name="name" autoComplete="name" maxLength={120} required /></label>
              <label>Email<input name="email" type="email" autoComplete="email" maxLength={254} required /></label>
              <label>Phone (optional)<input name="phone" type="tel" autoComplete="tel" maxLength={32} /></label>
              <label>Password<input name="password" type="password" autoComplete="new-password" minLength={12} maxLength={72} required /></label>
              <button disabled={busy}>{busy ? "Creating account..." : "Create account"}</button>
            </form>
            <nav><a href="#/login">Back to sign in</a></nav>
          </>
        )}
        {page === "forgot" && (
          <>
            <h1>Reset your password</h1>
            <p>Enter your email and, if an account exists, we will send a reset link.</p>
            <form onSubmit={(event) => void submit(event, async (form) => {
              await perform(
                () => accountApi.forgotPassword(String(form.get("email"))),
                "If an account exists for that address, a reset email will be sent.",
              );
            })}>
              <label>Email<input name="email" type="email" autoComplete="email" required /></label>
              <button disabled={busy}>Send reset link</button>
            </form>
            <nav><a href="#/login">Back to sign in</a></nav>
          </>
        )}
        {page === "verify" && (
          <>
            <h1>Verify your email</h1>
            <p>{notice || (error ? "This verification link could not be used." : "Checking your link...")}</p>
            <form onSubmit={(event) => void submit(event, async (form) => {
              await perform(
                () => accountApi.resendVerification(String(form.get("email"))),
                "If the address belongs to an unverified account, a verification email will be sent.",
              );
            })}>
              <label>Need another link? Enter your email<input name="email" type="email" required /></label>
              <button disabled={busy}>Resend verification</button>
            </form>
            <nav><a href="#/login">Continue to sign in</a></nav>
          </>
        )}
        {page === "reset" && (
          <>
            <h1>Choose a new password</h1>
            <form onSubmit={(event) => void submit(event, async (form) => {
              await perform(
                () => accountApi.resetPassword(tokenFromHash(), String(form.get("password"))),
                "Your password was reset. You can sign in now.",
              );
            })}>
              <label>New password<input name="password" type="password" autoComplete="new-password" minLength={12} maxLength={72} required /></label>
              <button disabled={busy}>Reset password</button>
            </form>
            <nav><a href="#/login">Back to sign in</a></nav>
          </>
        )}
        {page === "mfa-setup" && (
          <>
            <h1>Secure your administrator account</h1>
            <p>Add this account to an authenticator app, then enter its six-digit code.</p>
            {enrollment ? (
              <>
                <label>Setup key<input readOnly value={enrollment.secret} /></label>
                <a href={enrollment.otpauthUri}>Open in authenticator app</a>
                <form onSubmit={(event) => void submit(event, async (form) => {
                  await perform(async () => {
                    const result = await accountApi.confirmMfaEnrollment(String(form.get("code")));
                    setRecoveryCodes(result.recoveryCodes);
                    window.location.hash = "#/mfa-recovery";
                  }, "MFA enabled.");
                })}>
                  <label>Authenticator code<input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} required /></label>
                  <button disabled={busy}>Enable MFA</button>
                </form>
              </>
            ) : <p>Preparing secure enrollment...</p>}
          </>
        )}
        {page === "mfa-recovery" && (
          <>
            <h1>Save your recovery codes</h1>
            <p>Each code works once. Store them somewhere private; they will not be shown again.</p>
            <ul className="recovery-codes">{recoveryCodes.map((code) => <li key={code}>{code}</li>)}</ul>
            <a className="button-link" href="#/login">Continue to sign in</a>
          </>
        )}
        {page === "mfa" && (
          <>
            <h1>Administrator verification</h1>
            <p>Enter a code from your authenticator app or one unused recovery code.</p>
            <form onSubmit={(event) => void submit(event, async (form) => {
              await perform(async () => {
                await accountApi.verifyMfa(String(form.get("code")));
                setUser(await accountApi.me());
                window.location.hash = "#/onboarding";
              }, "Signed in.");
            })}>
              <label>Authenticator or recovery code<input name="code" autoComplete="one-time-code" maxLength={32} required /></label>
              <button disabled={busy}>Verify and sign in</button>
            </form>
          </>
        )}
        {page === "onboarding" && (
          <>
            <h1>Getting started</h1>
            {user && <p>Signed in as {user.name} ({user.email}).</p>}
            <h2>Customer</h2>
            <ol>
              <li>Verify your email and keep your sign-in details private.</li>
              <li>Review delivery details and pricing before confirming a booking.</li>
              <li>Keep pickup and delivery handoff codes private until the handoff.</li>
            </ol>
            <h2>Driver</h2>
            {user?.roles.includes("CUSTOMER") && (driverApplicationLoaded ? (
              driverApplication ? (
                <section className="application-card">
                  <p>Application status: <strong>{driverApplication.status.replaceAll("_", " ").toLowerCase()}</strong></p>
                  <p>Vehicle: {driverApplication.vehicleType.toLowerCase()} · Service area: {driverApplication.serviceArea}</p>
                  {driverApplication.status === "NEEDS_INFORMATION" && (
                    <>
                      <p>The administrator requested an update to your vehicle type or service area.</p>
                      <form onSubmit={(event) => void submit(event, async (form) => {
                        await perform(async () => {
                          const updated = await accountApi.updateDriverApplication(
                            driverVehicleType(form),
                            String(form.get("serviceArea")),
                          );
                          setDriverApplication(updated);
                        }, "Your updated application has been sent for review.");
                      })}>
                        <label>Vehicle type
                          <select name="vehicleType" defaultValue={driverApplication.vehicleType} required>
                            <option value="BICYCLE">Bicycle</option>
                            <option value="MOTORCYCLE">Motorcycle</option>
                            <option value="CAR">Car</option>
                            <option value="VAN">Van</option>
                          </select>
                        </label>
                        <label>Hong Kong service area
                          <input name="serviceArea" defaultValue={driverApplication.serviceArea} maxLength={120} required />
                        </label>
                        <button disabled={busy}>Update application</button>
                      </form>
                    </>
                  )}
                  {driverApplication.status === "APPROVED_PENDING_LAUNCH_GATES" && (
                    <p>This application is approved for now, but driver access remains disabled until launch requirements are met.</p>
                  )}
                  <p className="callout">Do not submit identity, licence, vehicle-registration, or insurance documents. This application does not activate a driver account.</p>
                </section>
              ) : (
                <>
                  <p>Apply with basic vehicle and service-area details only. Do not upload documents or identifiers.</p>
                  <form onSubmit={(event) => void submit(event, async (form) => {
                    await perform(async () => {
                      const created = await accountApi.submitDriverApplication(
                        driverVehicleType(form),
                        String(form.get("serviceArea")),
                      );
                      setDriverApplication(created);
                    }, "Your driver application has been submitted for review.");
                  })}>
                    <label>Vehicle type
                      <select name="vehicleType" defaultValue="" required>
                        <option value="" disabled>Select a vehicle</option>
                        <option value="BICYCLE">Bicycle</option>
                        <option value="MOTORCYCLE">Motorcycle</option>
                        <option value="CAR">Car</option>
                        <option value="VAN">Van</option>
                      </select>
                    </label>
                    <label>Hong Kong service area
                      <input name="serviceArea" maxLength={120} placeholder="Districts you can serve" required />
                    </label>
                    <button disabled={busy}>Apply to drive</button>
                  </form>
                </>
              )
            ) : <p>Driver applications are available to verified customers after sign-in.</p>)}
            {user?.roles.includes("ADMIN") && (
              <>
                <h3>Driver applications for review</h3>
                {adminApplications.length === 0 ? <p>No applications have been submitted.</p> : (
                  <ul className="application-list">
                    {adminApplications.map((application) => (
                      <li className="application-card" key={application.id}>
                        <strong>{application.applicantName}</strong>
                        <p>{application.applicantEmail}{application.applicantPhone ? ` · ${application.applicantPhone}` : ""}</p>
                        <p>{application.vehicleType.toLowerCase()} · {application.serviceArea}</p>
                        <p>Status: {application.status.replaceAll("_", " ").toLowerCase()}</p>
                        {["PENDING", "NEEDS_INFORMATION"].includes(application.status) && (
                          <div className="review-actions">
                            {([
                              ["NEEDS_INFORMATION", "Request information"],
                              ["APPROVED_PENDING_LAUNCH_GATES", "Approve, pending launch gates"],
                              ["REJECTED", "Reject"],
                            ] as const).map(([outcome, label]) => (
                              <button key={outcome} disabled={busy} onClick={() => void perform(async () => {
                                const updated = await accountApi.reviewDriverApplication(
                                  application.id,
                                  outcome,
                                );
                                setAdminApplications((current) =>
                                  current.map((item) => item.id === updated.id ? updated : item),
                                );
                              }, "Application review saved.")}>{label}</button>
                            ))}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                <p className="callout">Approval does not grant driver access or enable delivery operations.</p>
              </>
            )}
            <h2>Administrator</h2>
            <p>Administrator access is provisioned separately and requires authenticator MFA. Review tools are limited to metadata-only driver applications.</p>
            <p className="callout">Delivery booking and live operations are not enabled in this release.</p>
            <button onClick={() => void perform(accountApi.logout, "You are signed out.")}>Sign out</button>
          </>
        )}
        {notice && page !== "verify" && <p className="notice" role="status">{notice}</p>}
        {error && <p className="error" role="alert">{error}</p>}
      </section>
      <footer>Hong Kong · Account access</footer>
    </main>
  );
}
