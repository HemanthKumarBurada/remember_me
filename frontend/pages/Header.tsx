import { useState } from "react";
import Link from "next/link";
import styles from "../styles/Header.module.css";
import { FaFacebook, FaInstagram, FaYoutube, FaTwitter, FaPinterest, FaLinkedin } from "react-icons/fa";
import { SiThreads } from "react-icons/si";

export default function Header() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <header className={styles.header}>
      {/* Logo */}
      <div className={styles.logo}>☐ LOGO</div>

      {/* Navigation */}
      <nav className={styles.nav}>
        <a href="#">Features</a>

        {/* Dropdown for Channels */}
        <div 
          className={styles.dropdown} 
          onMouseEnter={() => setIsOpen(true)} 
          onMouseLeave={() => setIsOpen(false)}
        >
          <button className={styles.dropbtn}>
            Channels ⮟
          </button>

          {isOpen && (
            <div className={styles.dropdownContent}>
              <div className={styles.grid}>
                <Link href="#"><FaFacebook /> Facebook</Link>
                <Link href="#"><FaInstagram /> Instagram</Link>
                <Link href="#"><FaYoutube /> YouTube</Link>
                <Link href="#"><FaTwitter /> Twitter (X)</Link>
                <Link href="#"><FaPinterest /> Pinterest</Link>
                <Link href="#"><FaLinkedin /> LinkedIn</Link>
                <Link href="#"><SiThreads /> Threads</Link>
              </div>
            </div>
          )}
        </div>

        <a href="#">Blog</a>
        <a href="#">FAQs</a>
      </nav>

      {/* Auth buttons */}
      <div className={styles.actions}>
        <Link href="/login" className={styles.loginButton}>Log In</Link>
        <Link href="/register" className={styles.getStartedButton}>Get Started</Link>
      </div>
    </header>
  );
}