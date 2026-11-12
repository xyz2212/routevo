import { FormEvent, useEffect, useState } from "react";
import { accountApi, UserProfile } from "./client";

type Page = "login" | "register" | "forgot" | "verify" | "reset" | "onboarding";

function currentPage(): Page {
  const path = window.location.hash.split("?")[0].replace(/^#\/?/, "");
  const known: Page[] = ["login", "register", "forgot", "verify", "reset", "onboarding"];
  return known.includes(path as Page) ? (path as Page) : "login";
}

function tokenFromHash(): string {
  return new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("token") ?? "";
}

export default function App() {
  const [page, setPage] = useState<Page>(currentPage);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [user, setUser] = useState<UserProfile | null>(null);
  const [busy, setBusy] = useState(false);

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
      void accountApi.me().then(setUser).catch((cause: Error) => setError(cause.message));
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
                  await accountApi.login(String(form.get("email")), String(form.get("password")));
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
            <p>Driver applications and approval are not available yet. Do not submit identity or vehicle documents through this site.</p>
            <h2>Administrator</h2>
            <p>Administrator access is provisioned separately. Admin MFA and operational tools are not available yet.</p>
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
