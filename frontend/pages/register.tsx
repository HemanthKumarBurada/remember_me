import React, { useState, useEffect } from "react";
import Link from "next/link";
import axios from "axios";
import styles from "../styles/Register.module.css";

export default function SignupPage() {
  // Form state
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // UI state
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  // Password validation state
  const [passwordValidation, setPasswordValidation] = useState({
    minLength: false, hasUpper: false, hasLower: false, hasNumber: false, hasSpecial: false,
  });
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [passwordStrengthText, setPasswordStrengthText] = useState("");

  useEffect(() => {
    validatePassword(password);
  }, [password]);

  const validatePassword = (value: string) => {
    const minLength = value.length >= 8;
    const hasUpper = /[A-Z]/.test(value);
    const hasLower = /[a-z]/.test(value);
    const hasNumber = /\d/.test(value);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(value);

    setPasswordValidation({ minLength, hasUpper, hasLower, hasNumber, hasSpecial });

    const score = [minLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;
    setPasswordStrength(score);

    if (score <= 2) setPasswordStrengthText("Weak");
    else if (score <= 4) setPasswordStrengthText("Medium");
    else setPasswordStrengthText("Strong");
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");
    setMessage("");

    if (Object.values(passwordValidation).some(v => !v)) {
       setError("Please ensure your password meets all the requirements.");
       return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post("http://localhost:4000/auth/register", {
        fullName: username, email, password, confirmPassword,
      });
      setMessage(response.data.message || "Registration successful!");
      setUsername("");
      setEmail("");
      setPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      const serverError = err.response?.data?.message;
      setError(serverError ? (Array.isArray(serverError) ? serverError.join(', ') : serverError) : "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  const EyeIcon = () => (
    <svg height="25" width="30" viewBox="0 0 24 24" fill="none" stroke="#4877f5" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="12" rx="8" ry="5" /><circle cx="12" cy="12" r="2.5" fill="#4877f5" />
    </svg>
  );

  const EyeOffIcon = () => (
      <svg height="25" width="30" viewBox="0 0 24 24" fill="none" stroke="#4877f5" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <ellipse cx="12" cy="12" rx="8" ry="5" /><circle cx="12" cy="12" r="2.5" fill="#4877f5" />
          <line x1="4" y1="20" x2="20" y2="4" stroke="#bcbcbc" strokeWidth="2" />
      </svg>
  );

  return (
    <div className={styles.pageGifBg}>
      <div className={styles.centeredContent}>
        <div className={styles.loginCard}>
          <h2 className={styles.loginTitle}>Sign Up</h2>
          <form className={styles.loginForm} onSubmit={handleSubmit} noValidate>
            <div className={styles.formGroup}>
              <label className={styles.inputLabel} htmlFor="username">Full Name</label>
              <input type="text" id="username" placeholder="Full Name" className={styles.input} required value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className={styles.formGroup}>
              <label className={styles.inputLabel} htmlFor="email">Email</label>
              <input type="email" id="email" placeholder="username@gmail.com" className={styles.input} required value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className={styles.formGroup}>
              <label className={styles.inputLabel} htmlFor="password">Password</label>
              <div className={styles.passwordWrapper}>
                 <input type="password" id="password" placeholder="Enter your password" className={styles.input} required value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
            </div>

            {password.length > 0 && (
              <div className={styles.passwordStrengthContainer}>
                <div className={styles.strengthBarWrapper}>
                  <div className={styles.strengthBar}><div className={`${styles.strengthIndicator} ${styles[`strength-${passwordStrengthText.toLowerCase()}`]}`}></div></div>
                  <span className={`${styles.strengthText} ${styles[`strengthText-${passwordStrengthText.toLowerCase()}`]}`}>{passwordStrengthText}</span>
                </div>
                <ul className={styles.validationList}>
                  <li className={passwordValidation.minLength ? styles.valid : ''}>At least 8 characters</li>
                  <li className={passwordValidation.hasUpper ? styles.valid : ''}>One uppercase letter</li>
                  <li className={passwordValidation.hasLower ? styles.valid : ''}>One lowercase letter</li>
                  <li className={passwordValidation.hasNumber ? styles.valid : ''}>One number</li>
                  <li className={passwordValidation.hasSpecial ? styles.valid : ''}>One special character</li>
                </ul>
              </div>
            )}

            <div className={styles.formGroup}>
              <label className={styles.inputLabel} htmlFor="confirmPassword">Confirm Password</label>
              <div className={styles.passwordWrapper}>
                <input type={showConfirmPassword ? "text" : "password"} id="confirmPassword" placeholder="Re-enter your password" className={styles.input} required value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
                <span className={styles.toggleEye} role="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)}>
                  {showConfirmPassword ? <EyeIcon /> : <EyeOffIcon />}
                </span>
              </div>
            </div>

            <button type="submit" className={styles.button} disabled={loading}>{loading ? "Registering..." : "Register"}</button>

            <div className={styles.divider}>
              <span className={styles.dividerLine}></span>
              <span>or</span>
              <span className={styles.dividerLine}></span>
            </div>

            {/* --- GOOGLE BUTTON WITH SVG ICON --- */}
            <a href="http://localhost:4000/auth/google" className={styles.googleButton}>
              <svg className={styles.googleIcon} width="20" height="20" viewBox="0 0 24 24" focusable="false" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
                  <g>
                      <path d="M21.35 11.1h-9.17v2.82h5.63c-.24 1.41-1.28 2.61-2.75 3.12l.02.13 3.28 2.54.23.02c2.08-1.92 3.28-4.76 3.28-8.01 0-.56-.06-1.09-.15-1.62z" fill="#4285F4"></path>
                      <path d="M12.18 22c2.97 0 5.47-.99 7.3-2.69l-3.48-2.69c-.97.65-2.21 1.03-3.81 1.03-2.92 0-5.39-1.97-6.27-4.6l-.13.01-3.4 2.65-.04.12C4.61 19.98 8.11 22 12.18 22z" fill="#34A853"></path>
                      <path d="M5.91 13.05c-.22-.66-.34-1.37-.34-2.05s.12-1.39.33-2.05l-.01-.13-3.44-2.69-.11.05C1.39 7.89 1 9.4 1 11c0 1.63.39 3.18 1.11 4.56l3.81-2.51z" fill="#FBBC05"></path>
                      <path d="M12.18 6.89c2.14 0 3.58.92 4.41 1.7l3.23-3.15C18.55 3.84 15.89 2.5 12.18 2.5c-4.07 0-7.57 2.02-9.32 5.04l3.82 2.51c.75-2.28 2.88-4.16 5.5-4.16z" fill="#EA4335"></path>
                  </g>
              </svg>
              <span className={styles.googleButtonText}>Continue with Google</span>
            </a>
            {/* --- END OF GOOGLE BUTTON --- */}

            {error && <p className={styles.errorMessage}>{error}</p>}
            {message && <p className={styles.successMessage}>{message}</p>}
            <p className={styles.signupLink}>If you already have an account, please&nbsp;<Link href="/login" className={styles.link}>Log In</Link>.</p>
          </form>
        </div>
      </div>
    </div>
  );
}