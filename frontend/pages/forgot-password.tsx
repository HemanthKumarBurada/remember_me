import React, { useState, useEffect } from 'react';
import axios from 'axios';
import styles from '../styles/ForgotPassword.module.css';
import Link from 'next/link';

export default function ForgotPasswordPage() {
  const [email, setEmail]       = useState('');
  const [otp, setOtp]           = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage]   = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [step, setStep]         = useState(1);

  // --- Resend OTP Logic ---
  const [resendTimer, setResendTimer] = useState(60);
  const [canResend, setCanResend]     = useState(false);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (step === 2 && resendTimer > 0) {
      timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
    } else if (resendTimer === 0) {
      setCanResend(true);
    }
    return () => clearTimeout(timer);
  }, [step, resendTimer]);

  const handleResendOtp = async () => {
    if (!canResend) return;
    setLoading(true);
    setError('');
    setMessage('');
    try {
      await axios.post('http://localhost:4000/auth/resend-otp', { email });
      setMessage('A new OTP has been sent.');
      setCanResend(false);
      setResendTimer(60); // Reset timer
    } catch (err) {
      setError('Failed to resend OTP.');
    } finally {
      setLoading(false);
    }
  };
  // --- End of Resend Logic ---

  // State for password validation
  const [passwordValidation, setPasswordValidation] = useState({
    minLength: false, hasUpper: false, hasLower: false, hasNumber: false, hasSpecial: false,
  });
  const [passwordStrengthText, setPasswordStrengthText] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);


  useEffect(() => {
    if (newPassword.length > 0) {
      validatePassword(newPassword);
    }
  }, [newPassword]);

  const validatePassword = (value: string) => {
    const minLength = value.length >= 8;
    const hasUpper  = /[A-Z]/.test(value);
    const hasLower  = /[a-z]/.test(value);
    const hasNumber = /\d/.test(value);
    const hasSpecial= /[!@#$%^&*(),.?":{}|<>]/.test(value);

    setPasswordValidation({ minLength, hasUpper, hasLower, hasNumber, hasSpecial });
    const score = [minLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length;

    if (score <= 2) setPasswordStrengthText("Weak");
    else if (score <= 4) setPasswordStrengthText("Medium");
    else setPasswordStrengthText("Strong");
  };


  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const response = await axios.post('http://localhost:4000/auth/forgot-password', { email });
      setMessage(response.data.message);
      setStep(2);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to send OTP.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (Object.values(passwordValidation).some(v => !v)) {
      setError("Please ensure your password meets all the requirements.");
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('http://localhost:4000/auth/reset-password', {
        email, otp, newPassword, confirmPassword,
      });
      setMessage(response.data.message);
      setTimeout(() => {
        window.location.href = '/login';
      }, 2000);
    } catch (err: any) {
      const serverError = err.response?.data?.message;
      setError(serverError ? (Array.isArray(serverError) ? serverError.join(', ') : serverError) : "Failed to reset password.");
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
          {step === 1 ? (
            <>
              <h2 className={styles.loginTitle}>Forgot Password</h2>
              <p className={styles.instructions}>
                Enter your email address and we'll send you an OTP to reset your password.
              </p>
              <form className={styles.loginForm} onSubmit={handleSendOtp}>
                <div className={styles.formGroup}>
                  <label htmlFor="email" className={styles.inputLabel}>Email</label>
                  <input
                    id="email"
                    type="email"
                    placeholder="username@gmail.com"
                    className={styles.input}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
                <button type="submit" className={styles.button} disabled={loading}>
                  {loading ? 'Sending...' : 'Send OTP'}
                </button>
              </form>
            </>
          ) : (
            <>
              <h2 className={styles.loginTitle}>Reset Password</h2>
              <p className={styles.instructions}>
                An OTP has been sent to {email}.
              </p>
              <form className={styles.loginForm} onSubmit={handleResetPassword}>
                <div className={styles.formGroup}>
                  <label htmlFor="otp" className={styles.inputLabel}>OTP</label>
                  <input
                    id="otp"
                    type="text"
                    placeholder="Enter the 6-digit OTP"
                    className={styles.input}
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    required
                  />
                </div>

                <div className={styles.resendContainer}>
                    {canResend ? (
                        <button type="button" onClick={handleResendOtp} className={styles.resendButton} disabled={loading}>
                            Resend OTP
                        </button>
                    ) : (
                        <span>Resend OTP in {resendTimer}s</span>
                    )}
                </div>

                <div className={styles.formGroup}>
                  <label htmlFor="newPassword" className={styles.inputLabel}>New Password</label>
                  <div className={styles.passwordWrapper}>
                    <input
                      id="newPassword"
                      type={showPassword ? "text" : "password"}
                      placeholder="Enter new password"
                      className={styles.input}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                    />
                    <span className={styles.toggleEye} onClick={() => setShowPassword(!showPassword)}>
                        {showPassword ? <EyeIcon/> : <EyeOffIcon/>}
                    </span>
                  </div>
                </div>

                {newPassword.length > 0 && (
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
                  <label htmlFor="confirmPassword" className={styles.inputLabel}>Confirm New Password</label>
                   <div className={styles.passwordWrapper}>
                        <input
                        id="confirmPassword"
                        type={showConfirmPassword ? "text" : "password"}
                        placeholder="Confirm new password"
                        className={styles.input}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        />
                        <span className={styles.toggleEye} onClick={() => setShowConfirmPassword(!showConfirmPassword)}>
                            {showConfirmPassword ? <EyeIcon/> : <EyeOffIcon/>}
                        </span>
                   </div>
                </div>
                <button type="submit" className={styles.button} disabled={loading}>
                  {loading ? 'Resetting...' : 'Reset Password'}
                </button>
              </form>
            </>
          )}
          {message && <p className={styles.successMessage}>{message}</p>}
          {error && <p className={styles.errorMessage}>{error}</p>}
          <div className={styles.backToLogin}>
            <Link href="/login">Back to Login</Link>
          </div>
        </div>
      </div>
    </div>
  );
}