export type UserProfile = {
  email: string;
  name: string;
  phone: string | null;
  roles: string[];
  mfaSetupRequired: boolean;
};

type Message = { message: string };
type CsrfResponse = { headerName: string; token: string };
export type LoginResult = { stage: string; message: string };
export type MfaEnrollment = { secret: string; otpauthUri: string; expiresAt: string };
export type MfaEnrollmentResult = { recoveryCodes: string[]; message: string };
export type DriverVehicleType = "BICYCLE" | "MOTORCYCLE" | "CAR" | "VAN";
export type DriverApplicationStatus =
  | "PENDING"
  | "NEEDS_INFORMATION"
  | "APPROVED_PENDING_LAUNCH_GATES"
  | "REJECTED";
export type DriverApplicationReviewOutcome = Exclude<DriverApplicationStatus, "PENDING">;
export type DriverApplication = {
  id: string;
  applicantEmail: string;
  applicantName: string;
  applicantPhone: string | null;
  vehicleType: DriverVehicleType;
  serviceArea: string;
  status: DriverApplicationStatus;
  submittedAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
};

async function request<T>(path: string, method: string, body?: unknown): Promise<T> {
  const csrfResponse = await fetch("/api/auth/csrf", { credentials: "same-origin" });
  if (!csrfResponse.ok) {
    throw new Error("Unable to start a secure request. Please try again.");
  }
  const csrf = (await csrfResponse.json()) as CsrfResponse;
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      [csrf.headerName]: csrf.token,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 204) return undefined as T;
  const result: unknown = await response.json();
  if (!response.ok) {
    if (
      typeof result === "object" &&
      result !== null &&
      "message" in result &&
      typeof result.message === "string"
    ) {
      throw new Error(result.message);
    }
    throw new Error("The request could not be completed.");
  }
  return result as T;
}

export const accountApi = {
  register: (name: string, email: string, phone: string, password: string) =>
    request<Message>("/api/auth/register", "POST", { name, email, phone: phone || null, password }),
  login: (email: string, password: string) =>
    request<LoginResult>("/api/auth/login", "POST", { email, password }),
  me: async () => {
    const response = await fetch("/api/auth/me", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Please sign in to continue.");
    return (await response.json()) as UserProfile;
  },
  logout: () => request<Message>("/api/auth/logout", "POST"),
  verifyEmail: (token: string) => request<Message>("/api/auth/verify-email", "POST", { token }),
  resendVerification: (email: string) =>
    request<Message>("/api/auth/resend-verification", "POST", { email }),
  forgotPassword: (email: string) =>
    request<Message>("/api/auth/forgot-password", "POST", { email }),
  resetPassword: (token: string, password: string) =>
    request<Message>("/api/auth/reset-password", "POST", { token, password }),
  beginMfaEnrollment: () => request<MfaEnrollment>("/api/auth/mfa/enrollment", "POST"),
  confirmMfaEnrollment: (code: string) =>
    request<MfaEnrollmentResult>("/api/auth/mfa/enrollment/confirm", "POST", { code }),
  verifyMfa: (code: string) => request<LoginResult>("/api/auth/mfa/verify", "POST", { code }),
  driverApplication: () =>
    request<DriverApplication | undefined>("/api/auth/driver-application", "GET"),
  submitDriverApplication: (vehicleType: DriverVehicleType, serviceArea: string) =>
    request<DriverApplication>("/api/auth/driver-application", "POST", { vehicleType, serviceArea }),
  updateDriverApplication: (vehicleType: DriverVehicleType, serviceArea: string) =>
    request<DriverApplication>("/api/auth/driver-application", "PUT", { vehicleType, serviceArea }),
  driverApplicationsForReview: () =>
    request<DriverApplication[]>("/api/auth/admin/driver-applications", "GET"),
  reviewDriverApplication: (id: string, outcome: DriverApplicationReviewOutcome) =>
    request<DriverApplication>(`/api/auth/admin/driver-applications/${id}/review`, "POST", { outcome }),
};
